use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use log::info;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

use crate::types::{ChangedUsers, Permission};

/// SQLite state database row, mirroring the TypeORM schema of the TS version.
#[derive(Debug, Clone, Default)]
pub struct LocalUser {
    pub email: String,
    pub active: i64,
    pub display_name: String,
    pub inactive_count: i64,
    pub mail_perm_ro: String,
    pub mail_perm_rw: String,
    pub mail_perm_ro_inbox: String,
    pub mail_perm_ro_sent: String,
    pub mail_perm_sob: String,
    pub new_mail_perm_sob: String,
}

impl LocalUser {
    fn permission_value(&self, permission: Permission) -> &str {
        match permission {
            Permission::Ro => &self.mail_perm_ro,
            Permission::Rw => &self.mail_perm_rw,
            Permission::RoInbox => &self.mail_perm_ro_inbox,
            Permission::RoSent => &self.mail_perm_ro_sent,
        }
    }

    fn permission_value_mut(&mut self, permission: Permission) -> &mut String {
        match permission {
            Permission::Ro => &mut self.mail_perm_ro,
            Permission::Rw => &mut self.mail_perm_rw,
            Permission::RoInbox => &mut self.mail_perm_ro_inbox,
            Permission::RoSent => &mut self.mail_perm_ro_sent,
        }
    }
}

/// Timestamp of the current sync cycle in epoch milliseconds.
pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock before epoch").as_millis() as i64
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY NOT NULL,
    active INTEGER NOT NULL,
    displayName TEXT NOT NULL,
    inactiveCount INTEGER NOT NULL,
    mailPermRO TEXT NOT NULL,
    mailPermRW TEXT NOT NULL,
    mailPermROInbox TEXT NOT NULL,
    mailPermROSent TEXT NOT NULL,
    mailPermSOB TEXT NOT NULL,
    newMailPermSOB TEXT NOT NULL,
    lastSeen INTEGER NOT NULL
)";

const SELECT_COLUMNS: &str = "email, active, displayName, inactiveCount, \
     mailPermRO, mailPermRW, mailPermROInbox, mailPermROSent, mailPermSOB, newMailPermSOB";

/// Initialize the database connection, creating the schema if it does not exist yet.
pub async fn initialize(db_path: &str) -> Result<SqlitePool> {
    if let Some(dir) = Path::new(db_path).parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("Could not create database directory {}", dir.display()))?;
        }
    }
    let options = SqliteConnectOptions::new().filename(db_path).create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .connect_with(options)
        .await
        .with_context(|| format!("Could not open local user database {db_path}"))?;
    sqlx::query(SCHEMA).execute(&pool).await?;
    Ok(pool)
}

fn user_from_row(row: &sqlx::sqlite::SqliteRow) -> sqlx::Result<LocalUser> {
    Ok(LocalUser {
        email: row.try_get("email")?,
        active: row.try_get("active")?,
        display_name: row.try_get("displayName")?,
        inactive_count: row.try_get("inactiveCount")?,
        mail_perm_ro: row.try_get("mailPermRO")?,
        mail_perm_rw: row.try_get("mailPermRW")?,
        mail_perm_ro_inbox: row.try_get("mailPermROInbox")?,
        mail_perm_ro_sent: row.try_get("mailPermROSent")?,
        mail_perm_sob: row.try_get("mailPermSOB")?,
        new_mail_perm_sob: row.try_get("newMailPermSOB")?,
    })
}

async fn fetch_local_user(pool: &SqlitePool, mail: &str) -> Result<Option<LocalUser>> {
    let row = sqlx::query(&format!("SELECT {SELECT_COLUMNS} FROM users WHERE email = ?"))
        .bind(mail)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|row| user_from_row(&row)).transpose()?)
}

/// Get a user, marking it as checked in the current session (lastSeen update).
pub async fn get_user(pool: &SqlitePool, mail: &str, session_time: i64) -> Result<Option<LocalUser>> {
    let Some(user) = fetch_local_user(pool, mail).await? else { return Ok(None) };
    sqlx::query("UPDATE users SET lastSeen = ? WHERE email = ?")
        .bind(session_time)
        .bind(&user.email)
        .execute(pool)
        .await?;
    Ok(Some(user))
}

/// Add a user to the local database.
pub async fn create_user(
    pool: &SqlitePool,
    mail: &str,
    display_name: &str,
    active: i64,
    session_time: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO users (email, active, displayName, inactiveCount, mailPermRO, mailPermRW, \
         mailPermROInbox, mailPermROSent, mailPermSOB, newMailPermSOB, lastSeen) \
         VALUES (?, ?, ?, 0, '', '', '', '', '', '', ?)",
    )
    .bind(mail)
    .bind(active)
    .bind(display_name)
    .bind(session_time)
    .execute(pool)
    .await?;
    Ok(())
}

/// Change user activity status and inactive count in the local database.
pub async fn update_activity(pool: &SqlitePool, mail: &str, active: i64, inactive_count: i64) -> Result<()> {
    sqlx::query("UPDATE users SET active = ?, inactiveCount = ? WHERE email = ?")
        .bind(active)
        .bind(inactive_count)
        .bind(mail)
        .execute(pool)
        .await?;
    Ok(())
}

/// Change the user display name in the local database.
pub async fn update_display_name(pool: &SqlitePool, mail: &str, display_name: &str) -> Result<()> {
    sqlx::query("UPDATE users SET displayName = ? WHERE email = ?")
        .bind(display_name)
        .bind(mail)
        .execute(pool)
        .await?;
    Ok(())
}

/// Persist all columns of a user (used after permission changes).
pub async fn save_user(pool: &SqlitePool, user: &LocalUser) -> Result<()> {
    sqlx::query(
        "UPDATE users SET active = ?, displayName = ?, inactiveCount = ?, mailPermRO = ?, \
         mailPermRW = ?, mailPermROInbox = ?, mailPermROSent = ?, mailPermSOB = ?, \
         newMailPermSOB = ? WHERE email = ?",
    )
    .bind(user.active)
    .bind(&user.display_name)
    .bind(user.inactive_count)
    .bind(&user.mail_perm_ro)
    .bind(&user.mail_perm_rw)
    .bind(&user.mail_perm_ro_inbox)
    .bind(&user.mail_perm_ro_sent)
    .bind(&user.mail_perm_sob)
    .bind(&user.new_mail_perm_sob)
    .bind(&user.email)
    .execute(pool)
    .await?;
    Ok(())
}

/// Get all emails that have not been checked in the current session but are active.
pub async fn get_unchecked_active_users(pool: &SqlitePool, session_time: i64) -> Result<Vec<String>> {
    let rows = sqlx::query("SELECT email FROM users WHERE lastSeen != ? AND active != 0")
        .bind(session_time)
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().filter_map(|row| row.try_get("email").ok()).collect())
}

/// Update a user's send-on-behalf list in the local database (deduplicated).
pub async fn edit_local_user_permissions(pool: &SqlitePool, mail: &str, sob_emails: &[String]) -> Result<()> {
    let user = fetch_local_user(pool, mail)
        .await?
        .with_context(|| format!("Local user {mail} not found"))?;
    let mut sobs: Vec<String> = if user.new_mail_perm_sob.is_empty() {
        Vec::new()
    } else {
        user.new_mail_perm_sob.split(';').map(str::to_string).collect()
    };
    for sob in sob_emails {
        if !sobs.contains(sob) {
            sobs.push(sob.clone());
        }
    }
    sqlx::query("UPDATE users SET newMailPermSOB = ? WHERE email = ?")
        .bind(sobs.join(";"))
        .bind(mail)
        .execute(pool)
        .await?;
    Ok(())
}

/// Get all local users of which the SOB has changed in this session. Applies the
/// pending list (`newMailPermSOB`) to the stored list for every user.
///
/// Deviation from the TS source: the TS version cleared the pending list to an
/// empty string, which would report every non-empty SOB as changed (and wipe the
/// sender ACL) on the next sync cycle. Here the pending list is synced to the
/// applied value instead.
pub async fn get_sob_changed_users(pool: &SqlitePool) -> Result<Vec<LocalUser>> {
    let rows = sqlx::query(&format!("SELECT {SELECT_COLUMNS} FROM users")).fetch_all(pool).await?;
    let mut changed = Vec::new();
    for row in rows {
        let mut user = user_from_row(&row)?;
        let sob_changed = user.new_mail_perm_sob != user.mail_perm_sob;
        if sob_changed {
            info!(
                "SOB of {} changed from {} to {}.",
                user.email, user.mail_perm_sob, user.new_mail_perm_sob
            );
            user.mail_perm_sob = user.new_mail_perm_sob.clone();
        }
        user.new_mail_perm_sob = user.mail_perm_sob.clone();
        sqlx::query("UPDATE users SET mailPermSOB = ?, newMailPermSOB = ? WHERE email = ?")
            .bind(&user.mail_perm_sob)
            .bind(&user.new_mail_perm_sob)
            .bind(&user.email)
            .execute(pool)
            .await?;
        if sob_changed {
            changed.push(user);
        }
    }
    Ok(changed)
}

/// Get the changes in local user permissions and the updated user.
pub async fn get_permission_changes(
    pool: &SqlitePool,
    mail: &str,
    new_users: Vec<String>,
    permission: Permission,
) -> Result<(ChangedUsers, LocalUser)> {
    let mut user = fetch_local_user(pool, mail)
        .await?
        .with_context(|| format!("Local user {mail} not found"))?;

    let new_users: Vec<String> = new_users.into_iter().filter(|user| !user.is_empty()).collect();
    let stored: Vec<String> = user
        .permission_value(permission)
        .split(';')
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
        .collect();

    let new_users_changed: Vec<String> =
        new_users.iter().filter(|user| !stored.contains(user)).cloned().collect();
    let removed_users: Vec<String> =
        stored.iter().filter(|user| !new_users.contains(user)).cloned().collect();

    *user.permission_value_mut(permission) = new_users.join(";");
    Ok((ChangedUsers { new_users: new_users_changed, removed_users }, user))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_pool() -> SqlitePool {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let path = std::env::temp_dir()
            .join(format!("ldap-sync-test-{}-{id}.sqlite3", std::process::id()));
        let _ = std::fs::remove_file(&path);
        initialize(path.to_str().unwrap()).await.expect("db init")
    }

    #[tokio::test]
    async fn get_user_marks_last_seen() {
        let pool = test_pool().await;
        create_user(&pool, "a@example.local", "A", 1, 100).await.unwrap();
        create_user(&pool, "b@example.local", "B", 1, 100).await.unwrap();

        // Both users are unchecked for a new session.
        assert_eq!(
            get_unchecked_active_users(&pool, 300).await.unwrap(),
            ["a@example.local", "b@example.local"]
        );

        // Checking one user (lastSeen = session) excludes it from the unchecked list.
        let user = get_user(&pool, "a@example.local", 300).await.unwrap().unwrap();
        assert_eq!((user.active, user.display_name.as_str(), user.inactive_count), (1, "A", 0));
        assert_eq!(get_unchecked_active_users(&pool, 300).await.unwrap(), ["b@example.local"]);
    }

    #[tokio::test]
    async fn unchecked_excludes_deactivated_users() {
        let pool = test_pool().await;
        create_user(&pool, "c@example.local", "C", 1, 100).await.unwrap();
        update_activity(&pool, "c@example.local", 0, 255).await.unwrap();
        assert!(get_unchecked_active_users(&pool, 300).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn permission_changes_diff() {
        let pool = test_pool().await;
        create_user(&pool, "d@example.local", "D", 1, 100).await.unwrap();

        let (changed, user) = get_permission_changes(
            &pool,
            "d@example.local",
            vec!["dn1".into(), "dn2".into(), String::new()],
            Permission::Ro,
        )
        .await
        .unwrap();
        assert_eq!(changed.new_users, ["dn1", "dn2"]);
        assert!(changed.removed_users.is_empty());
        assert_eq!(user.mail_perm_ro, "dn1;dn2");
        save_user(&pool, &user).await.unwrap();

        let (changed, user) = get_permission_changes(
            &pool,
            "d@example.local",
            vec!["dn2".into(), "dn3".into()],
            Permission::Ro,
        )
        .await
        .unwrap();
        assert_eq!(changed.new_users, ["dn3"]);
        assert_eq!(changed.removed_users, ["dn1"]);
        assert_eq!(user.mail_perm_ro, "dn2;dn3");
    }

    #[tokio::test]
    async fn sob_accumulation_and_change_detection() {
        let pool = test_pool().await;
        create_user(&pool, "e@example.local", "E", 1, 100).await.unwrap();

        edit_local_user_permissions(&pool, "e@example.local", &["g1@x".into(), "g2@x".into()])
            .await
            .unwrap();
        // Duplicate SOB entries are not added twice.
        edit_local_user_permissions(&pool, "e@example.local", &["g2@x".into(), "g3@x".into()])
            .await
            .unwrap();

        let changed = get_sob_changed_users(&pool).await.unwrap();
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].email, "e@example.local");
        assert_eq!(changed[0].mail_perm_sob, "g1@x;g2@x;g3@x");
        // The pending list is synced to the applied value.
        assert_eq!(changed[0].new_mail_perm_sob, "g1@x;g2@x;g3@x");

        // Second pass: nothing pending anymore.
        assert!(get_sob_changed_users(&pool).await.unwrap().is_empty());
    }
}
