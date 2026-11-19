use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ldap3::{Ldap, LdapConnAsync, Scope, SearchEntry, drive};
use log::{error, info, warn};
use serde_json::json;
use sqlx::SqlitePool;
use tokio::time::sleep;

use crate::alias_sync::{AliasDictionary, get_alias_dictionary};
use crate::config::Config;
use crate::dovecot_api::DovecotApi;
use crate::local_db::{self, LocalUser, now_ms};
use crate::mailcow_api::MailcowApi;
use crate::types::{AdUser, BccMap, Mailbox, Permission};

const CONSOLE_LOG_LINE_LENGTH: usize = 40;
/// The alias dictionary is refreshed when it is older than one hour.
const ALIAS_REFRESH_INTERVAL: Duration = Duration::from_secs(3600);

fn console_log_line() -> String {
    "-".repeat(CONSOLE_LOG_LINE_LENGTH)
}

struct Ctx<'a> {
    config: &'a Config,
    ldap: &'a mut Ldap,
    local: &'a SqlitePool,
    mailcow: MailcowApi,
    dovecot: DovecotApi,
    aliases: Option<AliasDictionary>,
    bcc_maps: Vec<BccMap>,
    users: Vec<AdUser>,
    session_time: i64,
}

impl Ctx<'_> {
    fn alias_emails(&self, mail: &str) -> Vec<String> {
        self.aliases
            .as_ref()
            .and_then(|dict| dict.emails.get(mail).cloned())
            .unwrap_or_default()
    }

    async fn refresh_aliases(&mut self) -> Result<()> {
        let expired = self
            .aliases
            .as_ref()
            .is_some_and(|dict| dict.last_update.elapsed() > ALIAS_REFRESH_INTERVAL);
        if self.aliases.is_none() || expired {
            self.aliases = Some(get_alias_dictionary(&self.mailcow).await?);
        }
        Ok(())
    }
}

/// Initialize all (database) connections and run one full sync.
pub async fn run_sync(config: &Config) -> Result<()> {
    let line = console_log_line();

    info!("{line}\n SETTING UP CONNECTION WITH ACTIVE DIRECTORY\n{line}");
    let (connection, mut ldap) = LdapConnAsync::new(&config.ldap_uri)
        .await
        .context("Ran into an issue when connecting to Active Directory.")?;
    drive!(connection);
    ldap.simple_bind(&config.ldap_bind_dn, &config.ldap_bind_dn_password)
        .await
        .context("Ran into an issue when connecting to Active Directory.")?
        .success()
        .context("Ran into an issue when binding to Active Directory.")?;

    info!("{line}\n INITIALIZING DATABASES AND API CLIENTS \n{line}");
    let local = local_db::initialize("db/ldap-mailcow.sqlite3").await?;
    let mailcow = MailcowApi::new(&config.api_host, &config.api_key)?;
    let dovecot = DovecotApi::new(&config.doveadm_api_key);

    info!("{line}\n GETTING USERS FROM ACTIVE DIRECTORY\n{line}");
    let users = fetch_ad_users(&mut ldap, config).await?;

    info!("{line}\n SYNCING ALL USERS \n{line}");
    let session_time = now_ms();
    let mut ctx = Ctx {
        config,
        ldap: &mut ldap,
        local: &local,
        mailcow,
        dovecot,
        aliases: None,
        bcc_maps: Vec::new(),
        users,
        session_time,
    };
    synchronize_users(&ctx).await?;

    info!("{line}\n SYNCING ALL PERMISSIONS \n{line}");
    ctx.refresh_aliases().await?;
    ctx.bcc_maps = ctx.mailcow.get_bcc_maps().await?;
    synchronize_permissions(&mut ctx).await?;

    info!("Finished sync run.");
    Ok(())
}

/// Get all users from Active Directory, retrying empty responses.
async fn fetch_ad_users(ldap: &mut Ldap, config: &Config) -> Result<Vec<AdUser>> {
    let attributes = [
        "mail",
        "displayName",
        "userAccountControl",
        "mailPermRO",
        "mailPermRW",
        "mailPermROInbox",
        "mailPermROSent",
        "mailPermSOB",
        "memberOfFlattened",
    ];

    let mut retry_count = 0;
    let mut users: Vec<AdUser> = Vec::new();
    // Sometimes LDAP responses are empty; retry in those cases.
    while users.is_empty() && retry_count < config.max_ldap_retry_count {
        if retry_count > 0 {
            warn!("Retry number {retry_count} to get LDAP results");
        }
        retry_count += 1;
        let (entries, _) = ldap
            .search(&config.ldap_base_dn, Scope::Subtree, &config.ldap_filter, &attributes)
            .await?
            .success()?;
        users = entries.into_iter().map(|entry| ad_user_from_entry(SearchEntry::construct(entry))).collect();
    }
    if users.is_empty() {
        bail!("Ran into an issue when getting users from Active Directory.");
    }
    info!("Successfully got all users from Active Directory.");
    Ok(users)
}

fn ad_user_from_entry(entry: SearchEntry) -> AdUser {
    fn first(attrs: &HashMap<String, Vec<String>>, key: &str) -> String {
        attrs.get(key).and_then(|values| values.first()).cloned().unwrap_or_default()
    }
    fn list(attrs: &HashMap<String, Vec<String>>, key: &str) -> Vec<String> {
        attrs.get(key).cloned().unwrap_or_default()
    }

    AdUser {
        mail: first(&entry.attrs, "mail"),
        display_name: first(&entry.attrs, "displayName"),
        user_account_control: first(&entry.attrs, "userAccountControl").parse().unwrap_or(0),
        mail_perm_ro: first(&entry.attrs, "mailPermRO"),
        mail_perm_rw: first(&entry.attrs, "mailPermRW"),
        mail_perm_ro_inbox: first(&entry.attrs, "mailPermROInbox"),
        mail_perm_ro_sent: first(&entry.attrs, "mailPermROSent"),
        mail_perm_sob: first(&entry.attrs, "mailPermSOB"),
        member_of_flattened: list(&entry.attrs, "memberOfFlattened"),
    }
}

async fn ldap_search(ldap: &mut Ldap, base_dn: &str, attributes: &[&str]) -> Result<Vec<SearchEntry>> {
    let (entries, _) = ldap
        .search(base_dn, Scope::Subtree, "(objectClass=*)", attributes)
        .await?
        .success()?;
    Ok(entries.into_iter().map(SearchEntry::construct).collect())
}

/// Search Active Directory users on DN and return their mails.
async fn resolve_member_mails(
    ldap: &mut Ldap,
    member_dns: &[String],
    skip_mail: &str,
) -> Result<Vec<String>> {
    let mut mails = Vec::new();
    for dn in member_dns {
        let entries = ldap_search(ldap, dn, &["mail"]).await?;
        if let Some(mail) = entries
            .first()
            .and_then(|entry| entry.attrs.get("mail"))
            .and_then(|values| values.first())
        {
            // We do not want to set permissions for owner of the mailbox.
            if mail != skip_mail {
                mails.push(mail.clone());
            }
        }
        sleep(Duration::from_millis(10)).await;
    }
    Ok(mails)
}

/// Synchronize LDAP users with Mailcow mailboxes and the users stored in the local DB.
async fn synchronize_users(ctx: &Ctx<'_>) -> Result<()> {
    for user in &ctx.users {
        if user.mail.is_empty() {
            continue;
        }
        if let Err(e) = synchronize_single_user(ctx, user).await {
            error!("Ran into an issue when syncing user {}: {e:#}", user.mail);
        }
    }

    // Users that were not checked might have to be removed from mailcow.
    for email in local_db::get_unchecked_active_users(ctx.local, ctx.session_time).await? {
        if let Err(e) = synchronize_inactive_user(ctx, &email).await {
            error!("Ran into an issue when checking inactivity of {email}: {e:#}");
        }
    }
    info!("Successfully synced all users with Active Directory.");
    Ok(())
}

async fn synchronize_single_user(ctx: &Ctx<'_>, user: &AdUser) -> Result<()> {
    let mail = &user.mail;
    let display_name = &user.display_name;
    // Active: 0 = no incoming mail/no login, 1 = allow both,
    // 2 = custom state: allow incoming mail/no login
    let is_active: i64 = if user.user_account_control & 0b10 == 0b10 { 2 } else { 1 };

    let mut local = local_db::get_user(ctx.local, mail, ctx.session_time).await?;
    if local.is_none() {
        info!("Adding local user {mail} (active: {is_active})");
        local_db::create_user(ctx.local, mail, display_name, is_active, ctx.session_time).await?;
        local = Some(LocalUser {
            email: mail.clone(),
            active: is_active,
            display_name: display_name.clone(),
            ..LocalUser::default()
        });
    }
    let local = local.expect("local user just ensured");

    let mut mailbox = ctx.mailcow.get_mailbox(mail).await?;
    if mailbox.is_none() {
        info!("Adding Mailcow user {mail} (active: {is_active})");
        ctx.mailcow.create_mailbox(mail, display_name, is_active, 256).await?;
        mailbox = Some(Mailbox { active_int: is_active, name: display_name.clone() });
    }
    let mailbox = mailbox.expect("mailbox just ensured");

    if local.active != is_active {
        info!("Set {mail} to active state {is_active} in local user database");
        local_db::update_activity(ctx.local, mail, is_active, 0).await?;
    }

    if mailbox.active_int != is_active {
        info!("Set {mail} to active state {is_active} in Mailcow");
        ctx.mailcow.edit_mailbox(mail, json!({ "active": is_active })).await?;
    }

    if mailbox.name != *display_name {
        info!("Changed displayname for {mail} to {display_name} in Mailcow");
        ctx.mailcow.edit_mailbox(mail, json!({ "name": display_name })).await?;
    }

    if local.display_name != *display_name {
        info!("Changed displayname for {mail} to {display_name} in local database");
        local_db::update_display_name(ctx.local, mail, display_name).await?;
    }
    Ok(())
}

/// Handle users not present in this LDAP run: count missed cycles and deactivate
/// once the grace period (MAX_INACTIVE_COUNT) is exceeded.
async fn synchronize_inactive_user(ctx: &Ctx<'_>, email: &str) -> Result<()> {
    let mailbox = ctx.mailcow.get_mailbox(email).await?;
    let local = local_db::get_user(ctx.local, email, ctx.session_time)
        .await?
        .with_context(|| format!("Local user {email} not found"))?;

    let (new_active, new_inactive_count) = if local.inactive_count > ctx.config.max_inactive_count as i64 {
        (0, 255)
    } else {
        (2, local.inactive_count + 1)
    };

    if new_active == 0 {
        info!("Deactivated user {email} in local user database, not found in LDAP");
    } else {
        info!("Increased inactive count to {new_inactive_count} for {email}");
    }
    local_db::update_activity(ctx.local, email, new_active, new_inactive_count).await?;

    // Deviation from the TS source: it compared the pre-update activity state, so
    // mailcow was never actually deactivated once the grace period expired.
    if new_active == 0 && mailbox.is_some_and(|mailbox| mailbox.active_int != 0) {
        info!("Deactivated user {email} in Mailcow, not found in Active Directory");
        ctx.mailcow.edit_mailbox(email, json!({ "active": 0 })).await?;
    }
    Ok(())
}

/// Synchronize all the permissions with Active Directory.
async fn synchronize_permissions(ctx: &mut Ctx<'_>) -> Result<()> {
    let users = std::mem::take(&mut ctx.users);
    for user in &users {
        if let Err(e) = synchronize_user_permissions(ctx, user).await {
            error!("Ran into an issue when syncing permissions of {}: {e:#}", user.mail);
        }
    }

    for user in local_db::get_sob_changed_users(ctx.local).await? {
        if let Err(e) = apply_sob(ctx, &user).await {
            error!("Ran into an issue when syncing send on behalf of {}: {e:#}", user.email);
        }
    }
    info!("Successfully synced all permissions with Active Directory.");
    Ok(())
}

async fn synchronize_user_permissions(ctx: &mut Ctx<'_>, user: &AdUser) -> Result<()> {
    if !user.mail_perm_ro_inbox.is_empty() {
        synchronize_user_acl(ctx, user, Permission::RoInbox).await?;
    }
    if !user.mail_perm_ro_sent.is_empty() {
        synchronize_user_acl(ctx, user, Permission::RoSent).await?;
    }
    if !user.mail_perm_ro.is_empty() {
        synchronize_user_acl(ctx, user, Permission::Ro).await?;
    }
    if !user.mail_perm_rw.is_empty() {
        synchronize_user_acl(ctx, user, Permission::Rw).await?;
    }
    if !user.mail_perm_sob.is_empty() {
        synchronize_user_sob(ctx, user).await?;
    }
    if !user.member_of_flattened.is_empty() {
        synchronize_bcc_maps(ctx, user).await?;
    }
    Ok(())
}

/// Synchronize one ACL permission of a user with Active Directory.
async fn synchronize_user_acl(ctx: &mut Ctx<'_>, user: &AdUser, permission: Permission) -> Result<()> {
    let group_dn = user.permission_value(permission).to_string();
    let entries = ldap_search(ctx.ldap, &group_dn, &["memberFlattened"]).await?;
    let members = entries
        .first()
        .and_then(|entry| entry.attrs.get("memberFlattened").cloned())
        .unwrap_or_default();

    let (changed, local_user) =
        local_db::get_permission_changes(ctx.local, &user.mail, members, permission).await?;

    if !changed.new_users.is_empty() {
        info!("User(s) {} added to {} for {permission:?}", changed.new_users.join(", "), user.mail);
        let mails = resolve_member_mails(ctx.ldap, &changed.new_users, &user.mail).await?;
        ctx.dovecot.set_permissions(&user.mail, &mails, permission, false).await?;
    }

    if !changed.removed_users.is_empty() {
        info!("Removing User(s) {} from {} for {permission:?}", changed.removed_users.join(", "), user.mail);
        let mails = resolve_member_mails(ctx.ldap, &changed.removed_users, &user.mail).await?;
        ctx.dovecot.set_permissions(&user.mail, &mails, permission, true).await?;
    }

    // Only update the local user if everything went well.
    local_db::save_user(ctx.local, &local_user).await?;
    Ok(())
}

/// Synchronize the send-on-behalf list of all members of a user's SOB group.
async fn synchronize_user_sob(ctx: &mut Ctx<'_>, user: &AdUser) -> Result<()> {
    let group_dn = user.mail_perm_sob.clone();
    let entries = ldap_search(ctx.ldap, &group_dn, &["memberFlattened"]).await?;
    let sobs: Vec<String> =
        std::iter::once(user.mail.clone()).chain(ctx.alias_emails(&user.mail)).collect();

    for entry in entries {
        let members = entry.attrs.get("memberFlattened").cloned().unwrap_or_default();
        for member_dn in members {
            let member_entries = ldap_search(ctx.ldap, &member_dn, &["mail"]).await?;
            let Some(member_mail) = member_entries
                .first()
                .and_then(|entry| entry.attrs.get("mail"))
                .and_then(|values| values.first())
                .cloned()
            else {
                continue;
            };
            local_db::edit_local_user_permissions(ctx.local, &member_mail, &sobs).await?;
        }
    }
    Ok(())
}

/// Apply changed send-on-behalf lists to mailcow.
async fn apply_sob(ctx: &Ctx<'_>, user: &LocalUser) -> Result<()> {
    let sobs: Vec<String> =
        user.mail_perm_sob.split(';').filter(|sob| !sob.is_empty()).map(str::to_string).collect();
    ctx.mailcow.edit_mailbox(&user.email, json!({ "sender_acl": sobs })).await?;
    Ok(())
}

/// Synchronize the BCC maps of a user and its aliases with Active Directory.
async fn synchronize_bcc_maps(ctx: &mut Ctx<'_>, user: &AdUser) -> Result<()> {
    for group_dn in &user.member_of_flattened {
        if !group_dn.contains("MAIL-BCC-self") {
            continue;
        }
        let aliases = ctx.alias_emails(&user.mail);
        for destination in std::iter::once(user.mail.clone()).chain(aliases) {
            let bcc_map = BccMap {
                active: 1,
                bcc_dest: destination.clone(),
                local_dest: destination.clone(),
                map_type: "sender".to_string(),
            };
            // Deviation from the TS source: it returned from the whole function when a
            // map already existed, skipping all remaining groups and aliases.
            if ctx.bcc_maps.contains(&bcc_map) {
                continue;
            }
            ctx.mailcow.add_bcc_map(&bcc_map).await?;
            ctx.bcc_maps.push(bcc_map);
        }
    }
    Ok(())
}
