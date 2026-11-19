use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use tokio::time::{Duration, sleep};

use crate::types::Permission;

const DOVEADM_BASE_URL: &str = "http://172.22.1.250:9000/doveadm/v1";
/// Maximum number of doveadm requests sent in a single POST.
const DOVEADM_MAX_REQUEST_SIZE: usize = 10;

/// Rights granted for read-only ACLs (lookup/read/write/write-seen).
const RO_RIGHTS: [&str; 4] = ["lookup", "read", "write", "write-seen"];
/// Additional rights for read-write ACLs.
const RW_EXTRA_RIGHTS: [&str; 6] =
    ["write-deleted", "insert", "post", "expunge", "create", "delete"];

/// Rights granted for a permission type (the same set `set_permissions` applies).
pub fn rights_for(permission: Permission) -> Vec<&'static str> {
    let mut rights: Vec<&'static str> = RO_RIGHTS.to_vec();
    if permission == Permission::Rw {
        rights.extend(RW_EXTRA_RIGHTS);
    }
    rights
}

/// Client for the doveadm HTTP API used to manage Dovecot ACLs.
pub struct DovecotApi {
    http: reqwest::Client,
    base_url: String,
    authorization: String,
}

impl DovecotApi {
    pub fn new(doveadm_api_key: &str) -> Self {
        Self::with_base_url(doveadm_api_key, DOVEADM_BASE_URL)
    }

    pub(crate) fn with_base_url(doveadm_api_key: &str, base_url: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.to_string(),
            authorization: format!("X-Dovecot-API {}", STANDARD.encode(doveadm_api_key)),
        }
    }

    async fn post(&self, payload: Value) -> Result<Value> {
        let response = self
            .http
            .post(&self.base_url)
            .header("Content-Type", "application/json")
            .header("Authorization", &self.authorization)
            .json(&payload)
            .send()
            .await
            .context("doveadm request failed")?;
        let status = response.status();
        let body: Value = response
            .json()
            .await
            .with_context(|| format!("doveadm returned invalid JSON (HTTP {status})"))?;
        if !status.is_success() {
            bail!("doveadm request failed (HTTP {status}): {body}");
        }
        if body.is_null() {
            bail!("doveadm returned an empty response (HTTP {status})");
        }
        Ok(body)
    }

    /// Get all mailbox subfolders of a mail, excluding shared folders.
    pub async fn get_mailbox_subfolders(&self, mail: &str) -> Result<Vec<String>> {
        let payload = json!([["mailbox-list", { "user": mail }, "get-subfolders"]]);
        let response = self.post(payload).await?;

        let Some(entries) = response.get(0).and_then(|row| row.get(1)).and_then(Value::as_array)
        else {
            bail!("Unexpected doveadm mailbox-list response: {response}");
        };

        let mut subfolders = Vec::new();
        for entry in entries {
            if let Some(mailbox) = entry.get("mailbox").and_then(Value::as_str) {
                if mailbox.starts_with("Shared") {
                    continue;
                }
                subfolders.push(mailbox.to_string());
            }
        }
        Ok(subfolders)
    }

    /// Read the ACL entries of one folder (`doveadm acl-get`). Returns
    /// `(id, rights)` pairs, e.g. `("user=a@example.local", ["lookup", "read", ...])`.
    pub async fn get_acl(&self, mail: &str, folder: &str) -> Result<Vec<(String, Vec<String>)>> {
        let payload = json!([["acl-get", { "user": mail, "mailbox": folder }, "acl-get"]]);
        let response = self.post(payload).await?;

        let Some(entries) = response.get(0).and_then(|row| row.get(1)).and_then(Value::as_array)
        else {
            bail!("Unexpected doveadm acl-get response: {response}");
        };

        let mut acls = Vec::new();
        for entry in entries {
            let id = entry.get("id").and_then(Value::as_str);
            let rights: Option<Vec<String>> = entry
                .get("rights")
                .and_then(Value::as_array)
                .map(|rights| rights.iter().filter_map(Value::as_str).map(String::from).collect());
            match (id, rights) {
                (Some(id), Some(rights)) => acls.push((id.to_string(), rights)),
                _ => bail!("Unexpected acl-get entry in doveadm response: {entry}"),
            }
        }
        Ok(acls)
    }

    /// Set (or remove) read/write permissions in dovecot.
    ///
    /// Deviation from the TS source: a truthiness bug there made every permission
    /// type fall through to the "all subfolders + PermRO" branch; here ROInbox
    /// applies to INBOX only, ROSent to Sent only, and RO/RW to all subfolders.
    pub async fn set_permissions(
        &self,
        mail: &str,
        users: &[String],
        permission: Permission,
        remove: bool,
    ) -> Result<()> {
        let (subfolders, permission_tag): (Vec<String>, &str) = match permission {
            // Dovecot matches INBOX case-insensitively, so a single entry covers
            // every casing a client may have used.
            Permission::RoInbox => (vec!["INBOX".into()], "PermROInbox"),
            Permission::RoSent => (vec!["Sent".into()], "PermROSent"),
            Permission::Ro | Permission::Rw => {
                let subfolders = self.get_mailbox_subfolders(mail).await?;
                let tag = if permission == Permission::Rw { "PermRW" } else { "PermRO" };
                (subfolders, tag)
            }
        };

        let rights = rights_for(permission);

        let command = if remove { "aclRemove" } else { "aclSet" };
        let mut requests = Vec::new();
        for subfolder in &subfolders {
            for user in users {
                // Dovecot API requests are batchable: [command, data, tag].
                requests.push(json!([
                    command,
                    {
                        "user": mail,
                        "id": format!("user={user}"),
                        "mailbox": subfolder,
                        "right": rights,
                    },
                    format!("{permission_tag}_{mail}_{user}"),
                ]));
            }
        }

        // Requests are broken up in smaller pieces to respect the max size.
        // NOTE from Dovecot docs: it is not guaranteed that requests are processed in
        // order or that the doveadm server does not crash.
        for chunk in requests.chunks(DOVEADM_MAX_REQUEST_SIZE) {
            self.post(Value::Array(chunk.to_vec())).await?;
            sleep(Duration::from_millis(10)).await;
        }
        Ok(())
    }
}
