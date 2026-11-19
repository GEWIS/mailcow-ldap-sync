# mailcow-ldap-sync

Syncs LDAP (e.g. Active Directory) users into [mailcow-dockerized](https://github.com/mailcow/mailcow-dockerized). Rust port of [custommailcow-ldap](https://github.com/gewis/custommailcow-ldap), without the LDAP-login configuration: this tool only keeps mailcow in sync with your directory, it does not wire up Dovecot/SOGo LDAP authentication.

It periodically:

- creates mailcow mailboxes for LDAP users and deactivates ones that disappear from LDAP (with a configurable grace period),
- AD-disabled accounts (`userAccountControl` `ACCOUNTDISABLE`) keep receiving mail but lose login (mailcow active state `2`); only accounts that disappear from LDAP are deactivated after the grace period,
- syncs display names,
- syncs mailbox ACLs (read/read-write on folders) through the doveadm HTTP API from `mailPermRO`, `mailPermROInbox`, `mailPermROSent`, `mailPermRW` group attributes,
- syncs *send on behalf* (`sender_acl`) from `mailPermSOB` groups (including mailcow aliases),
- adds sender BCC maps for AD groups named `*MAIL-BCC-self*`,
- keeps its own SQLite state database in `db/` so mailcow is only touched when something actually changed,
- runs a **nightly consolidation** (report-only) that compares what mailcow and
  dovecot actually serve with the SQLite state and logs every difference.

## Prerequisites

The ACL sync uses the doveadm HTTP API of the dovecot container (fixed address `http://172.22.1.250:9000`, as in the upstream project). Enable it once by adding the following to `data/conf/dovecot/extra.conf` and restarting `dovecot-mailcow`:

```
# Let doveadm listen on 9000 for HTTP API
service doveadm {
  inet_listener http {
    port = 9000
  }
}
doveadm_api_key = <DOVEADM_API_KEY>
```

## Usage

1. Extend your `docker-compose.override.yml`:

   ```yaml
   ldap-mailcow:
     build: ./mailcow-ldap-sync
     network_mode: host
     container_name: mailcowcustomized_ldap-mailcow
     depends_on:
       - nginx-mailcow
     volumes:
       - ./data/ldap:/app/db:rw
     environment:
       - LDAP-MAILCOW_LDAP_URI=ldap://dc.example.local
       - LDAP-MAILCOW_LDAP_BASE_DN=OU=Mail Users,DC=example,DC=local
       - LDAP-MAILCOW_LDAP_BIND_DN=CN=Bind DN,CN=Users,DC=example,DC=local
       - LDAP-MAILCOW_LDAP_BIND_DN_PASSWORD=BindPassword
       - LDAP-MAILCOW_API_HOST=https://mailcow.example.local
       - LDAP-MAILCOW_API_KEY=XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX
       - LDAP-MAILCOW_MAX_INACTIVE_COUNT=3
       - LDAP-MAILCOW_MAX_LDAP_RETRY_COUNT=3
       - DOVEADM_API_KEY=XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX
       - LDAP-MAILCOW_SYNC_INTERVAL=300
   ```

2. Start the container: `docker-compose up -d ldap-mailcow`.
3. Check the logs.

### Environment variables

- `LDAP-MAILCOW_LDAP_URI` - LDAP URI (`ldap://` or `ldaps://`).
- `LDAP-MAILCOW_LDAP_BASE_DN` - base DN where user accounts can be found.
- `LDAP-MAILCOW_LDAP_BIND_DN` / `LDAP-MAILCOW_LDAP_BIND_DN_PASSWORD` - bind account used to browse for users.
- `LDAP-MAILCOW_API_HOST` - mailcow API url (read/write access required).
- `LDAP-MAILCOW_API_KEY` - mailcow API key (read/write).
- `LDAP-MAILCOW_MAX_INACTIVE_COUNT` - number of missed sync cycles before a user missing from LDAP is deactivated.
- `LDAP-MAILCOW_MAX_LDAP_RETRY_COUNT` - how often to retry when the LDAP search returns no users.
- `DOVEADM_API_KEY` - doveadm HTTP API key for the ACL endpoints.
- `LDAP-MAILCOW_SYNC_INTERVAL` (optional) - seconds between sync cycles. Unset or `0`: run once and exit.
- `LDAP-MAILCOW_CONSOLIDATE_INTERVAL` (optional) - seconds between consolidation runs. Defaults to `86400` (nightly); `0` disables.
- `LDAP-MAILCOW_LDAP_FILTER` (optional) - LDAP filter to apply, defaults to `(&(objectClass=user)(objectCategory=person))`.

## Consolidation

After every sync cycle (and once before exiting in run-once mode), once the
consolidation interval has elapsed, the tool compares what mailcow and the
doveadm HTTP API actually report with the local SQLite state and **logs every
difference as a warning**. It checks, per stored user:

- the mailbox exists in mailcow,
- the `active` state and display name match,
- `sender_acl` matches the recorded send-on-behalf list,
- the Dovecot ACLs match the recorded `mailPerm*` members: for every recorded
  member, the expected rights on the expected folders (`INBOX` for
  `mailPermROInbox`, `Sent` for `mailPermROSent`, every non-shared folder for
  `mailPermRO`/`mailPermRW`).

The consolidation is **report-only**: it never writes to mailcow, dovecot, or
the local database. It catches drift the incremental sync cannot see, e.g.
manual changes in the mailcow UI, doveadm requests that silently failed inside
a 200 response, and folders created after the last permission change. Items it
cannot verify (missing API fields, unreadable ACLs) are counted and logged
instead of being reported as drift.

## Limitations

- **Two-way sync**: users from LDAP are added to mailcow, not vice-versa — by design. This might be coming soon.
- Coming from the upstream project, login with LDAP credentials in Dovecot/SOGo is **not** provided by this tool.

## Deviations from the TypeScript source

The port fixes bugs where the TS behavior clearly diverged from the intent:

- Dovecot ACL folders: ROInbox applies to `INBOX`/`Inbox`, ROSent to `Sent`, RO/RW
  to all non-shared folders (the TS truthiness bug applied all folders to every type).
- Inactive-user expiry: mailcow mailboxes are actually deactivated once the grace
  period expires.
- BCC maps: existing maps no longer abort the remaining groups/aliases.
- Inactive-user SOB pending list: the pending send-on-behalf list is synced to the
  applied value, so repeated cycles do not wipe `sender_acl`.
- ACL group members are stored in the local database as resolved mail addresses
  instead of member DNs, so the ACLs of members deleted from Active Directory are
  actually removed. Members that no longer exist or have no mail address are skipped
  with a warning instead of aborting the permission sync. The first run after
  upgrading re-diffs the stored entries once.
- Send-on-behalf lists are replaced each cycle by the union of the SOB groups a user
  is in, so removals from SOB groups propagate to `sender_acl`. When a SOB group
  cannot be read, updates are additive only, so a transient failure never wipes
  sender ACLs.
- doveadm HTTP failures (non-2xx status, invalid or empty JSON) abort the sync
  instead of silently counting as success.
- The alias dictionary handles multi-target aliases (`goto` with several
  comma-separated targets) and expands nested alias chains transitively, so an
  alias behind another alias is included in the SOB list and BCC maps of the
  mailbox the chain ends at. Group members are resolved in batched LDAP searches
  (chunks of 50) instead of one search per member.
- The mailcow-MariaDB signature module (`editUserSignatures`) was dead code and is
  not ported. The dovecot/SOGo login configuration templates were removed entirely.

## Building

```sh
cargo build --release
```

Requires Rust 1.75+. The Docker image builds a static musl binary.

## CI and releases

- `lint-and-build` runs clippy (`-D warnings`), tests, and a release build on pushes and PRs to `main`/`develop`.
- `semantic-release` runs on pushes to `main`: [semantic-release](https://semantic-release.gitbook.io/) derives the next version from [conventional commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, …), tags it, creates a GitHub release, and builds/publishes the Docker image via the [GEWIS/actions](https://github.com/GEWIS/actions) `docker-release` workflow to `ghcr.io/<owner>/mailcow-ldap-sync` (`:latest` + `:<version>`).
