use anyhow::{Context, Result, bail};
use rand::Rng;
use serde_json::{Value, json};

use crate::types::{Alias, BccMap, Mailbox};

/// ACL flags granted to every newly created mailbox (mirrors the TS client).
const DEFAULT_USER_ACL: [&str; 7] = [
    "spam_alias",
    "spam_score",
    "spam_policy",
    "delimiter_action",
    "quarantine",
    "quarantine_notification",
    "app_passwds",
];

const PASSWORD_LENGTH: usize = 32;

fn generate_password(length: usize) -> String {
    const CHARACTERS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| CHARACTERS[rng.gen_range(0..CHARACTERS.len())] as char)
        .collect()
}

/// Thin client for the mailcow REST API (`/api/v1`).
pub struct MailcowApi {
    http: reqwest::Client,
    base_url: String,
    api_key: String,
}

impl MailcowApi {
    pub fn new(api_host: &str, api_key: &str) -> Result<Self> {
        // The client always appends `api/v1/{route}` itself; accept a host with
        // or without the `/api/v1` suffix (the TS client required the suffix).
        let mut base_url = api_host.trim_end_matches('/').trim_end_matches("/api/v1").to_string();
        base_url.push('/');
        Ok(Self { http: reqwest::Client::new(), base_url, api_key: api_key.to_string() })
    }

    async fn get(&self, route: &str) -> Result<Value> {
        let url = format!("{}api/v1/{route}", self.base_url);
        let response = self
            .http
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .send()
            .await
            .context("Mailcow API request failed")?;
        let body: Value = response.json().await.context("Mailcow API returned invalid JSON")?;
        ensure_ok(&body)?;
        Ok(body)
    }

    async fn post(&self, route: &str, payload: Value) -> Result<Value> {
        let url = format!("{}api/v1/{route}", self.base_url);
        let response = self
            .http
            .post(&url)
            .header("X-API-Key", &self.api_key)
            .json(&payload)
            .send()
            .await
            .context("Mailcow API request failed")?;
        let body: Value = response.json().await.context("Mailcow API returned invalid JSON")?;
        ensure_ok(&body)?;
        Ok(body)
    }

    /// Get a single mailbox, `None` when it does not exist.
    pub async fn get_mailbox(&self, mail: &str) -> Result<Option<Mailbox>> {
        let body = self.get(&format!("get/mailbox/{mail}")).await?;
        let entry = match body {
            Value::Array(items) => items.into_iter().next(),
            value => Some(value),
        };
        let Some(Value::Object(entry)) = entry else { return Ok(None) };
        // An error object or an empty object means the mailbox was not found.
        if entry.is_empty() {
            return Ok(None);
        }
        if matches!(entry.get("type").and_then(Value::as_str), Some("danger") | Some("error")) {
            return Ok(None);
        }
        Ok(Some(Mailbox {
            active_int: entry.get("active_int").and_then(Value::as_i64).unwrap_or(0),
            name: entry.get("name").and_then(Value::as_str).unwrap_or_default().to_string(),
        }))
    }

    /// Create a mailbox with a random password and set the default user ACL.
    pub async fn create_mailbox(&self, mail: &str, name: &str, active: i64, quota: i64) -> Result<()> {
        let password = generate_password(PASSWORD_LENGTH);
        let Some((local_part, domain)) = mail.split_once('@') else {
            bail!("Invalid mail address: {mail}");
        };
        self.post(
            "add/mailbox",
            json!({
                "local_part": local_part,
                "domain": domain,
                "name": name,
                "quota": quota,
                "password": password,
                "password2": password,
                // Active: 0 = no incoming mail/no login, 1 = allow both,
                // 2 = custom state: allow incoming mail/no login
                "active": active,
                "force_pw_update": false,
                "tls_enforce_in": false,
                "tls_enforce_out": false,
                "authsource": "keycloak",
            }),
        )
        .await?;

        self.post(
            "edit/user-acl",
            json!({
                "items": mail,
                "attr": { "user_acl": DEFAULT_USER_ACL },
            }),
        )
        .await?;
        Ok(())
    }

    /// Edit mailbox attributes (active state, name, sender ACL, ...).
    pub async fn edit_mailbox(&self, mail: &str, attr: Value) -> Result<()> {
        self.post("edit/mailbox", json!({ "items": [mail], "attr": attr })).await?;
        Ok(())
    }

    /// Get all aliases currently registered in mailcow.
    pub async fn get_aliases(&self) -> Result<Vec<Alias>> {
        let body = self.get("get/alias/all").await?;
        serde_json::from_value(body).context("Unexpected alias response from Mailcow API")
    }

    /// Get all BCC maps currently registered in mailcow.
    pub async fn get_bcc_maps(&self) -> Result<Vec<BccMap>> {
        let body = self.get("get/bcc/all").await?;
        serde_json::from_value(body).context("Unexpected bcc map response from Mailcow API")
    }

    pub async fn add_bcc_map(&self, map: &BccMap) -> Result<()> {
        self.post("add/bcc", serde_json::to_value(map)?).await?;
        Ok(())
    }
}

/// Mailcow POST responses are arrays of `{type, msg}` objects; `danger`/`error` are failures.
fn ensure_ok(body: &Value) -> Result<()> {
    let items: Vec<&Value> = match body {
        Value::Array(items) => items.iter().collect(),
        value => vec![value],
    };
    for item in items {
        let kind = item.get("type").and_then(Value::as_str);
        if matches!(kind, Some("danger") | Some("error")) {
            let msg = match item.get("msg") {
                Some(Value::Array(parts)) => parts
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", "),
                Some(Value::String(msg)) => msg.clone(),
                _ => String::new(),
            };
            bail!("Mailcow API error ({kind:?}): {msg}");
        }
    }
    Ok(())
}
