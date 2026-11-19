use std::collections::{BTreeSet, HashMap};

use anyhow::Result;
use log::{info, warn};
use sqlx::SqlitePool;

use crate::config::Config;
use crate::dovecot_api::{DovecotApi, rights_for};
use crate::local_db::{self, LocalUser};
use crate::mailcow_api::{MailcowApi, ObservedMailbox};
use crate::types::Permission;

/// A divergence between what mailcow/dovecot serve and what the local database
/// records. The consolidation is report-only: it never writes to mailcow,
/// dovecot, or the local database. Fixing a drift means clearing the affected
/// local database column by hand, so the next regular sync re-applies it.
#[derive(Debug, PartialEq, Eq)]
pub struct Drift {
    pub mail: String,
    pub detail: String,
}

impl Drift {
    fn new(mail: &str, detail: impl Into<String>) -> Self {
        Self { mail: mail.to_string(), detail: detail.into() }
    }
}

/// Result of one consolidation run.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Consolidation {
    /// Number of local users checked.
    pub users: usize,
    /// Divergences between mailcow/dovecot and the local database.
    pub drifts: Vec<Drift>,
    /// Items that could not be verified (missing API fields, unreadable ACLs).
    pub unverifiable: usize,
}

/// Run the nightly consolidation: compare what mailcow/dovecot serve with the
/// local database and log every difference. Report-only.
pub async fn run(config: &Config) -> Result<Consolidation> {
    info!("[consolidation] comparing mailcow/dovecot with the local database (report-only)");
    let local = local_db::initialize(local_db::DB_PATH).await?;
    let mailcow = MailcowApi::new(&config.api_host, &config.api_key)?;
    let dovecot = DovecotApi::new(&config.doveadm_api_key);
    let consolidation = consolidate(&mailcow, &dovecot, &local).await?;
    for drift in &consolidation.drifts {
        warn!("[consolidation] {}: {}", drift.mail, drift.detail);
    }
    info!(
        "[consolidation] checked {} users: {} drift(s), {} item(s) could not be verified",
        consolidation.users, consolidation.drifts.len(), consolidation.unverifiable
    );
    info!("[consolidation] report-only: nothing was changed");
    Ok(consolidation)
}

/// Compare the local database with what mailcow and doveadm actually report.
pub async fn consolidate(
    mailcow: &MailcowApi,
    dovecot: &DovecotApi,
    local: &SqlitePool,
) -> Result<Consolidation> {
    let users = local_db::get_all_users(local).await?;
    let mut by_mail: HashMap<String, ObservedMailbox> = HashMap::new();
    for mailbox in mailcow.get_all_mailboxes().await? {
        match &mailbox.username {
            Some(username) => {
                by_mail.insert(username.clone(), mailbox);
            }
            None => warn!("[consolidation] skipping mailcow mailbox entry without username"),
        }
    }

    let mut consolidation = Consolidation { users: users.len(), ..Consolidation::default() };
    for user in &users {
        match by_mail.get(&user.email) {
            None => consolidation
                .drifts
                .push(Drift::new(&user.email, "mailbox does not exist in mailcow; the next sync recreates it")),
            Some(mailbox) => {
                if mailbox.active_int != user.active {
                    consolidation.drifts.push(Drift::new(
                        &user.email,
                        format!(
                            "mailcow active state is {}, local database says {}",
                            mailbox.active_int, user.active
                        ),
                    ));
                }
                if mailbox.name != user.display_name {
                    consolidation.drifts.push(Drift::new(
                        &user.email,
                        format!(
                            "mailcow display name is {:?}, local database says {:?}",
                            mailbox.name, user.display_name
                        ),
                    ));
                }
                match &mailbox.sender_acl {
                    Some(actual) => consolidation.drifts.extend(sender_acl_drifts(user, actual)),
                    None => {
                        consolidation.unverifiable += 1;
                        warn!(
                            "[consolidation] {}: mailcow did not report sender_acl, cannot verify",
                            user.email
                        );
                    }
                }
            }
        }
        let (acl_drifts, unverifiable) = acl_drifts(dovecot, user).await?;
        consolidation.drifts.extend(acl_drifts);
        consolidation.unverifiable += unverifiable;
    }
    Ok(consolidation)
}

/// Compare the recorded send-on-behalf list with the mailbox's actual
/// `sender_acl`. The mailbox owner can always send as themselves, so their own
/// address is excluded from both sides before comparing.
fn sender_acl_drifts(user: &LocalUser, actual: &[String]) -> Vec<Drift> {
    let desired: BTreeSet<&str> = user
        .mail_perm_sob
        .split(';')
        .map(str::trim)
        .filter(|entry| !entry.is_empty() && *entry != user.email)
        .collect();
    let actual: BTreeSet<&str> = actual
        .iter()
        .map(|entry| entry.trim())
        .filter(|entry| !entry.is_empty() && *entry != user.email)
        .collect();
    let missing: Vec<&str> = desired.difference(&actual).copied().collect();
    let unexpected: Vec<&str> = actual.difference(&desired).copied().collect();
    if missing.is_empty() && unexpected.is_empty() {
        return Vec::new();
    }
    vec![Drift::new(
        &user.email,
        format!(
            "mailcow sender_acl is missing {missing:?} and has unexpected {unexpected:?} (local database holds {desired:?})"
        ),
    )]
}

/// The ACL groups of a local user that has any recorded permission.
fn recorded_permissions(user: &LocalUser) -> Vec<(Permission, Vec<String>)> {
    let candidates = [
        (Permission::RoInbox, &user.mail_perm_ro_inbox),
        (Permission::RoSent, &user.mail_perm_ro_sent),
        (Permission::Ro, &user.mail_perm_ro),
        (Permission::Rw, &user.mail_perm_rw),
    ];
    candidates
        .into_iter()
        .filter(|(_, list)| !list.is_empty())
        .map(|(permission, list)| {
            (
                permission,
                list.split(';').filter(|entry| !entry.is_empty()).map(String::from).collect(),
            )
        })
        .collect()
}

/// Verify the Dovecot ACLs of one local user against the recorded permissions.
/// Returns the drifts and `1` when the user could not be verified at all
/// (no folders reported, or doveadm not readable).
async fn acl_drifts(dovecot: &DovecotApi, user: &LocalUser) -> Result<(Vec<Drift>, usize)> {
    let perms = recorded_permissions(user);
    if perms.is_empty() {
        return Ok((Vec::new(), 0));
    }

    let folders = match dovecot.get_mailbox_subfolders(&user.email).await {
        Ok(folders) => folders,
        Err(e) => {
            warn!("[consolidation] {}: could not list dovecot folders ({e:#}), cannot verify ACLs", user.email);
            return Ok((Vec::new(), 1));
        }
    };
    if folders.is_empty() {
        return Ok((Vec::new(), 1));
    }

    // One acl-get per folder, cached across the permission types. Folders whose
    // ACL cannot be read are excluded from the comparison (counted as
    // unverifiable) instead of being reported as drift.
    let mut acl_by_folder: HashMap<String, Vec<(String, Vec<String>)>> = HashMap::new();
    let mut unreadable = 0usize;
    for permission in [Permission::RoInbox, Permission::RoSent, Permission::Ro, Permission::Rw] {
        if !perms.iter().any(|(candidate, _)| *candidate == permission) {
            continue;
        }
        for folder in target_folders(&folders, permission) {
            if let std::collections::hash_map::Entry::Vacant(entry) =
                acl_by_folder.entry(folder.clone())
            {
                match dovecot.get_acl(&user.email, folder).await {
                    Ok(acl) => {
                        entry.insert(acl);
                    }
                    Err(e) => {
                        warn!("[consolidation] {}: could not read ACL of {folder} ({e:#})", user.email);
                        unreadable += 1;
                    }
                }
            }
        }
    }

    let drifts = compare_acls(user, &folders, &acl_by_folder, &perms);
    Ok((drifts, unreadable))
}

/// Compare the recorded permissions with the observed folders and ACL entries.
/// Folders without a readable ACL entry are skipped (they were counted as
/// unverifiable by the caller).
fn compare_acls(
    user: &LocalUser,
    folders: &[String],
    acl_by_folder: &HashMap<String, Vec<(String, Vec<String>)>>,
    perms: &[(Permission, Vec<String>)],
) -> Vec<Drift> {
    let mut drifts = Vec::new();
    for (permission, members) in perms {
        for folder in target_folders(folders, *permission) {
            let Some(entries) = acl_by_folder.get(folder) else { continue };
            for member in members {
                let entry =
                    entries.iter().find(|(id, _)| id.eq_ignore_ascii_case(&format!("user={member}")));
                let Some((_, rights)) = entry else {
                    drifts.push(Drift::new(
                        &user.email,
                        format!("{permission:?} ACL missing for {member} on {folder}"),
                    ));
                    continue;
                };
                let expected_rights = rights_for(*permission);
                let lacking: Vec<&str> = expected_rights
                    .iter()
                    .copied()
                    .filter(|right| !rights.iter().any(|stored| stored.as_str() == *right))
                    .collect();
                if !lacking.is_empty() {
                    drifts.push(Drift::new(
                        &user.email,
                        format!("{permission:?} ACL for {member} on {folder} lacks {lacking:?}"),
                    ));
                }
            }
        }
    }
    drifts
}

/// The folders a permission is expected on. ROInbox applies to INBOX, ROSent to
/// Sent (both looked up case-insensitively; a folder that does not exist yet
/// cannot be verified), RO/RW to every non-shared folder that exists today.
fn target_folders(folders: &[String], permission: Permission) -> Vec<&String> {
    match permission {
        Permission::Ro | Permission::Rw => folders.iter().collect(),
        Permission::RoInbox => folders.iter().filter(|f| f.eq_ignore_ascii_case("INBOX")).collect(),
        Permission::RoSent => folders.iter().filter(|f| f.eq_ignore_ascii_case("Sent")).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn user(mail: &str, sob: &str) -> LocalUser {
        LocalUser { email: mail.into(), active: 1, display_name: mail.into(), mail_perm_sob: sob.into(), ..LocalUser::default() }
    }

    fn list(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|entry| entry.to_string()).collect()
    }

    /// ACL entry helper: one `user=<mail>` id with the rights of `permission`.
    fn entry(mail: &str, permission: Permission) -> (String, Vec<String>) {
        ("user=".to_string() + mail, rights_for(permission).into_iter().map(String::from).collect())
    }

    #[test]
    fn sender_acl_matches() {
        let local = user("a@x", "b@y;c@y");
        assert!(sender_acl_drifts(&local, &list(&["b@y", "c@y"])).is_empty());
        // The owner's own address is not meaningful in sender_acl on either side.
        assert!(sender_acl_drifts(&local, &list(&["b@y", "c@y", "a@x"])).is_empty());
    }

    #[test]
    fn sender_acl_drift_reported() {
        let local = user("a@x", "b@y;c@y");
        let drifts = sender_acl_drifts(&local, &list(&["b@y", "d@y"]));
        assert_eq!(drifts.len(), 1);
        assert_eq!(drifts[0].mail, "a@x");
        assert!(drifts[0].detail.contains("missing") && drifts[0].detail.contains("c@y"));
        assert!(drifts[0].detail.contains("unexpected") && drifts[0].detail.contains("d@y"));
        // An empty actual list clears nothing silently: every desired entry is missing.
        let drifts = sender_acl_drifts(&local, &[]);
        assert_eq!(drifts.len(), 1);
        assert!(drifts[0].detail.contains("b@y") && drifts[0].detail.contains("c@y"));
    }

    #[test]
    fn acl_missing_and_lacking_rights() {
        let mut local = user("a@x", "");
        local.mail_perm_ro_sent = "b@y".into();
        local.mail_perm_rw = "b@y;c@y".into();
        let folders = vec!["Sent".to_string(), "Projects".to_string()];
        let acl_by_folder = HashMap::from([
            ("Sent".to_string(), vec![]),
            (
                "Projects".to_string(),
                vec![
                    entry("b@y", Permission::Rw),
                    // c@y only holds read-only rights but is recorded as RW.
                    entry("c@y", Permission::Ro),
                ],
            ),
        ]);
        let perms = recorded_permissions(&local);
        let drifts = compare_acls(&local, &folders, &acl_by_folder, &perms);
        assert_eq!(
            drifts,
            vec![
                // Sent has no ACL entries at all.
                Drift::new("a@x", "RoSent ACL missing for b@y on Sent"),
                Drift::new("a@x", "Rw ACL missing for b@y on Sent"),
                Drift::new("a@x", "Rw ACL missing for c@y on Sent"),
                // c@y is recorded as RW but only holds RO rights.
                Drift::new(
                    "a@x",
                    "Rw ACL for c@y on Projects lacks [\"write-deleted\", \"insert\", \"post\", \"expunge\", \"create\", \"delete\"]"
                ),
            ]
        );
    }

    #[test]
    fn acl_clean_when_all_rights_present() {
        let mut local = user("a@x", "");
        local.mail_perm_ro = "b@y".into();
        local.mail_perm_ro_sent = "c@y".into();
        let folders = vec!["INBOX".to_string(), "Sent".to_string()];
        let acl_by_folder = HashMap::from([
            ("INBOX".to_string(), vec![entry("b@y", Permission::Ro)]),
            (
                "Sent".to_string(),
                vec![entry("b@y", Permission::Ro), entry("c@y", Permission::Ro)],
            ),
        ]);
        let perms = recorded_permissions(&local);
        let drifts = compare_acls(&local, &folders, &acl_by_folder, &perms);
        assert!(drifts.is_empty(), "{drifts:?}");
    }

    #[test]
    fn recorded_permissions_ignores_empty() {
        let mut local = user("a@x", "");
        local.mail_perm_ro = "b@y;c@y".into();
        local.mail_perm_ro_inbox = "".into();
        let perms = recorded_permissions(&local);
        assert_eq!(perms, vec![(Permission::Ro, vec!["b@y".to_string(), "c@y".to_string()])]);
        assert!(recorded_permissions(&user("a@x", "")).is_empty());
    }

    #[tokio::test]
    async fn end_to_end_against_mock_server() {
        let pool = local_db::test_pool().await;
        let mut a = user("a@x", "b@y;c@y");
        a.mail_perm_ro_inbox = "b@y".into();
        a.mail_perm_ro_sent = "b@y".into();
        local_db::create_user(&pool, &a.email, &a.display_name, a.active, 100).await.unwrap();
        local_db::save_user(&pool, &a).await.unwrap();
        local_db::create_user(&pool, "b@x", "B", 2, 100).await.unwrap();
        local_db::create_user(&pool, "c@x", "C", 0, 100).await.unwrap();

        // Mailcow reports: a@x drifted only in sender_acl (missing c@y), b@x
        // matches its local record (active 2), c@x is missing entirely.
        let mailcow_json = json!([
            { "username": "a@x", "active_int": 1, "name": "a@x", "sender_acl": ["b@y"] },
            { "username": "b@x", "active_int": 2, "name": "B", "sender_acl": [] },
        ])
        .to_string();
        let mailbox_list = json!([["tag", [{ "mailbox": "INBOX" }, { "mailbox": "Sent" }]]]).to_string();
        // INBOX carries the expected RO entry for b@y; Sent carries nothing.
        let acl_inbox =
            json!([["tag", [{ "id": "user=b@y", "rights": ["lookup", "read", "write", "write-seen"] }]]])
                .to_string();
        let acl_sent = json!([["tag", []]]).to_string();

        let port = spawn_mock(move |path, body| {
            if path.contains("get/mailbox/all") {
                mailcow_json.clone()
            } else if body.contains("\"mailbox-list\"") {
                mailbox_list.clone()
            } else if body.contains("\"Sent\"") {
                acl_sent.clone()
            } else {
                acl_inbox.clone()
            }
        });

        let mailcow = MailcowApi::new(&format!("http://127.0.0.1:{port}"), "mock-key").unwrap();
        let dovecot =
            DovecotApi::with_base_url("mock-key", &format!("http://127.0.0.1:{port}/doveadm/v1"));
        let result = consolidate(&mailcow, &dovecot, &pool).await.unwrap();

        assert_eq!(result.users, 3);
        assert_eq!(result.drifts.len(), 3, "unexpected drifts: {result:?}");
        let mut drifts = result.drifts;
        drifts
            .sort_by(|l, r| (l.mail.as_str(), l.detail.as_str()).cmp(&(r.mail.as_str(), r.detail.as_str())));
        // Sorted by (mail, detail): both a@x drifts first (R < m), then c@x.
        assert_eq!(drifts[0].mail, "a@x");
        assert!(drifts[0].detail.contains("RoSent ACL missing for b@y on Sent"), "{}", drifts[0].detail);
        assert_eq!(drifts[1].mail, "a@x");
        assert!(drifts[1].detail.contains("missing [\"c@y\"]"), "{}", drifts[1].detail);
        assert_eq!(drifts[2].mail, "c@x");
        assert!(drifts[2].detail.contains("does not exist in mailcow"));
        assert_eq!(result.unverifiable, 0);
    }

    /// Minimal HTTP server that answers every request with the JSON the closure
    /// produces for the request path/body. One connection per request.
    fn spawn_mock<F>(respond: F) -> u16
    where
        F: Fn(&str, &str) -> String + Send + 'static,
    {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten().take(16) {
                let mut stream = stream;
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 4096];
                // Read until the end of the headers, then the declared body.
                let header_end = loop {
                    let read = stream.read(&mut chunk).unwrap();
                    buffer.extend_from_slice(&chunk[..read]);
                    match buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                        Some(position) => break position + 4,
                        None if read == 0 => panic!("mock server: incomplete request"),
                        None => continue,
                    }
                };
                let request = String::from_utf8_lossy(&buffer).to_string();
                let head = &request[..header_end];
                let path = head.lines().next().unwrap().split(' ').nth(1).unwrap().to_string();
                let mut content_length = 0usize;
                for line in head.lines() {
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            content_length = value.trim().parse().unwrap_or(0);
                        }
                    }
                }
                while buffer.len() < header_end + content_length {
                    let read = stream.read(&mut chunk).unwrap();
                    if read == 0 {
                        break;
                    }
                    buffer.extend_from_slice(&chunk[..read]);
                }
                let body = String::from_utf8_lossy(&buffer[header_end..]).to_string();
                let response_body = respond(&path, &body);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        port
    }
}
