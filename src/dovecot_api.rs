use anyhow::Result;
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

/// Client for the doveadm HTTP API used to manage Dovecot ACLs.
pub struct DovecotApi {
    http: reqwest::Client,
    base_url: String,
    authorization: String,
}

impl DovecotApi {
    pub fn new(doveadm_api_key: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: DOVEADM_BASE_URL.to_string(),
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
            .await?;
        Ok(response.json().await.unwrap_or(Value::Null))
    }

    /// Get all mailbox subfolders of a mail, excluding shared folders.
    pub async fn get_mailbox_subfolders(&self, mail: &str) -> Result<Vec<String>> {
        let payload = json!([["mailbox-list", { "user": mail }, "get-subfolders"]]);
        let response = self.post(payload).await?;

        let mut subfolders = Vec::new();
        if let Some(entries) = response.get(0).and_then(|row| row.get(1)).and_then(Value::as_array) {
            for entry in entries {
                if let Some(mailbox) = entry.get("mailbox").and_then(Value::as_str) {
                    if mailbox.starts_with("Shared") {
                        continue;
                    }
                    subfolders.push(mailbox.to_string());
                }
            }
        }
        Ok(subfolders)
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
            Permission::RoInbox => (vec!["INBOX".into(), "Inbox".into()], "PermROInbox"),
            Permission::RoSent => (vec!["Sent".into()], "PermROSent"),
            Permission::Ro | Permission::Rw => {
                let subfolders = self.get_mailbox_subfolders(mail).await?;
                let tag = if permission == Permission::Rw { "PermRW" } else { "PermRO" };
                (subfolders, tag)
            }
        };

        let mut rights: Vec<&str> = RO_RIGHTS.to_vec();
        if permission == Permission::Rw {
            rights.extend(RW_EXTRA_RIGHTS);
        }

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
