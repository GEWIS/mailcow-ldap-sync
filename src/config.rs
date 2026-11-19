use anyhow::{Context, Result};

const ENV_PREFIX: &str = "LDAP-MAILCOW_";
const DEFAULT_LDAP_FILTER: &str = "(&(objectClass=user)(objectCategory=person))";

/// Runtime configuration, built from environment variables.
pub struct Config {
    pub ldap_uri: String,
    pub ldap_base_dn: String,
    pub ldap_bind_dn: String,
    pub ldap_bind_dn_password: String,
    pub ldap_filter: String,
    pub api_host: String,
    pub api_key: String,
    pub doveadm_api_key: String,
    pub max_inactive_count: u32,
    pub max_ldap_retry_count: u32,
    /// `LDAP-MAILCOW_SYNC_INTERVAL` in seconds. `None` or `0`: run once and exit.
    pub sync_interval: Option<u64>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let required = |name: &str| -> Result<String> {
            let key = format!("{ENV_PREFIX}{name}");
            std::env::var(&key).with_context(|| format!("Required environment value {key} is not set. "))
        };

        let max_inactive_count: u32 = required("MAX_INACTIVE_COUNT")?
            .parse()
            .context("LDAP-MAILCOW_MAX_INACTIVE_COUNT must be a number")?;
        let max_ldap_retry_count: u32 = required("MAX_LDAP_RETRY_COUNT")?
            .parse()
            .context("LDAP-MAILCOW_MAX_LDAP_RETRY_COUNT must be a number")?;
        let sync_interval = match std::env::var(format!("{ENV_PREFIX}SYNC_INTERVAL")) {
            Ok(value) => {
                Some(value.parse::<u64>().context("LDAP-MAILCOW_SYNC_INTERVAL must be a number")?)
            }
            Err(_) => None,
        };

        Ok(Self {
            ldap_uri: required("LDAP_URI")?,
            ldap_base_dn: required("LDAP_BASE_DN")?,
            ldap_bind_dn: required("LDAP_BIND_DN")?,
            ldap_bind_dn_password: required("LDAP_BIND_DN_PASSWORD")?,
            ldap_filter: std::env::var(format!("{ENV_PREFIX}LDAP_FILTER"))
                .unwrap_or_else(|_| DEFAULT_LDAP_FILTER.to_string()),
            api_host: required("API_HOST")?,
            api_key: required("API_KEY")?,
            doveadm_api_key: std::env::var("DOVEADM_API_KEY")
                .context("Required environment value DOVEADM_API_KEY is not set. ")?,
            max_inactive_count,
            max_ldap_retry_count,
            sync_interval,
        })
    }
}
