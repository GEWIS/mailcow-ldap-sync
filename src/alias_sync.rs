use std::collections::{BTreeSet, HashMap};

use anyhow::Result;

use crate::mailcow_api::MailcowApi;
use crate::types::Alias;

/// Maps every email to all alias addresses that (transitively) deliver to it:
/// `{ 'email': ['alias1', 'alias2'] }`.
pub struct AliasDictionary {
    pub emails: HashMap<String, Vec<String>>,
}

/// Build the alias dictionary from all aliases currently registered in mailcow.
pub async fn get_alias_dictionary(api: &MailcowApi) -> Result<AliasDictionary> {
    Ok(build_alias_dictionary(api.get_aliases().await?))
}

/// Aliases with multiple targets (`goto: "a@x,b@x"`) are indexed for every target,
/// and alias chains (`a -> b -> mailbox`) are expanded transitively, so nested
/// aliases end up in the list of the mailbox at the end of the chain.
fn build_alias_dictionary(aliases: Vec<Alias>) -> AliasDictionary {
    // Direct mapping: every alias target -> the alias addresses pointing at it.
    let mut direct: HashMap<String, Vec<String>> = HashMap::new();
    for alias in &aliases {
        for target in alias.goto.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            direct.entry(target.to_string()).or_default().push(alias.address.clone());
        }
    }

    let mut emails = HashMap::with_capacity(direct.len());
    for target in direct.keys().cloned().collect::<Vec<_>>() {
        // Expand alias chains transitively; the set also guards against cycles.
        let mut resolved: BTreeSet<String> = BTreeSet::new();
        let mut frontier: Vec<String> = direct[&target].clone();
        while let Some(address) = frontier.pop() {
            if resolved.insert(address.clone()) {
                if let Some(nested) = direct.get(&address) {
                    frontier.extend(nested.iter().cloned());
                }
            }
        }
        emails.insert(target, resolved.into_iter().collect());
    }
    AliasDictionary { emails }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alias(address: &str, goto: &str) -> Alias {
        Alias { address: address.into(), goto: goto.into() }
    }

    #[test]
    fn multi_target_and_nested_aliases() {
        let dict = build_alias_dictionary(vec![
            alias("direct@x", "user@x"),
            alias("multi@x", "user@x , user2@x"),
            alias("nested@x", "direct@x"),
        ]);
        // Nested@x delivers through direct@x to user@x, so it belongs to user@x too.
        assert_eq!(dict.emails["user@x"], ["direct@x", "multi@x", "nested@x"]);
        assert_eq!(dict.emails["user2@x"], ["multi@x"]);
    }

    #[test]
    fn alias_cycles_terminate() {
        let dict = build_alias_dictionary(vec![alias("a@x", "b@x"), alias("b@x", "a@x")]);
        // Self-referential entries are harmless: a real mailbox address is never
        // itself an alias address, so these keys are never looked up.
        assert_eq!(dict.emails["a@x"], ["a@x", "b@x"]);
        assert_eq!(dict.emails["b@x"], ["a@x", "b@x"]);
    }
}
