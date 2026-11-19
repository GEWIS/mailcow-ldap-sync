use serde::Deserialize;

/// The Active Directory ACL permission attributes. The SOB attribute is handled
/// separately through mailcow sender ACLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    Ro,
    Rw,
    RoInbox,
    RoSent,
}

/// One user entry from the Active Directory search.
#[derive(Debug, Clone, Default)]
pub struct AdUser {
    pub mail: String,
    pub display_name: String,
    pub user_account_control: u32,
    pub mail_perm_ro: String,
    pub mail_perm_rw: String,
    pub mail_perm_ro_inbox: String,
    pub mail_perm_ro_sent: String,
    pub mail_perm_sob: String,
    pub member_of_flattened: Vec<String>,
}

impl AdUser {
    pub fn permission_value(&self, permission: Permission) -> &str {
        match permission {
            Permission::Ro => &self.mail_perm_ro,
            Permission::Rw => &self.mail_perm_rw,
            Permission::RoInbox => &self.mail_perm_ro_inbox,
            Permission::RoSent => &self.mail_perm_ro_sent,
        }
    }
}

/// Difference between the local database state and Active Directory for one permission.
#[derive(Debug, Clone, Default)]
pub struct ChangedUsers {
    pub new_users: Vec<String>,
    pub removed_users: Vec<String>,
}

/// Mailcow mailbox, reduced to the fields this sync uses.
#[derive(Debug, Clone, Deserialize)]
pub struct Mailbox {
    pub active_int: i64,
    #[serde(default)]
    pub name: String,
}

/// Mailcow alias entry.
#[derive(Debug, Clone, Deserialize)]
pub struct Alias {
    pub address: String,
    pub goto: String,
}

/// Mailcow BCC map.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, serde::Serialize)]
pub struct BccMap {
    pub active: i64,
    pub bcc_dest: String,
    pub local_dest: String,
    #[serde(rename = "type")]
    pub map_type: String,
}
