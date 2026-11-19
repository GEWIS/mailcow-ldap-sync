mod alias_sync;
mod config;
mod consolidation;
mod dovecot_api;
mod local_db;
mod mailcow_api;
mod sync;
mod types;

use std::time::{Duration, Instant};

use anyhow::Result;
use log::{error, info};

use crate::config::Config;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    let config = Config::from_env()?;
    let sync_interval = config.sync_interval;
    let consolidate_interval = config.consolidate_interval;
    let mut last_consolidation: Option<Instant> = None;

    loop {
        if let Err(e) = sync::run_sync(&config).await {
            error!("Sync run failed: {e:#}");
            if sync_interval.is_none() {
                return Err(e);
            }
        } else {
            info!("Finished!");
        }

        // Nightly consolidation: report drift between mailcow/dovecot and the
        // local database. Runs after a sync cycle, once the interval elapsed.
        if consolidate_interval > 0
            && last_consolidation.is_none_or(|last| last.elapsed().as_secs() >= consolidate_interval)
        {
            if let Err(e) = consolidation::run(&config).await {
                error!("Consolidation run failed: {e:#}");
            }
            last_consolidation = Some(Instant::now());
        }

        match sync_interval {
            Some(seconds) if seconds > 0 => tokio::time::sleep(Duration::from_secs(seconds)).await,
            _ => break,
        }
    }
    Ok(())
}
