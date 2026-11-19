use std::collections::HashMap;
use std::time::Instant;

use anyhow::Result;

use crate::mailcow_api::MailcowApi;

/// Maps every email to all its aliases:
/// `{ 'email': ['alias1', 'alias2'] }`.
pub struct AliasDictionary {
    pub emails: HashMap<String, Vec<String>>,
    pub last_update: Instant,
}

/// Build the alias dictionary from all aliases currently registered in mailcow.
pub async fn get_alias_dictionary(api: &MailcowApi) -> Result<AliasDictionary> {
    let aliases = api.get_aliases().await?;
    let mut emails: HashMap<String, Vec<String>> = HashMap::new();
    for alias in aliases {
        emails.entry(alias.goto).or_default().push(alias.address);
    }
    Ok(AliasDictionary { emails, last_update: Instant::now() })
}
