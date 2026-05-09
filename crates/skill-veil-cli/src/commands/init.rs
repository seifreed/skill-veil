//! Wiring for `skill-veil init` and `skill-veil rules update / status`.
//!
//! These commands all touch the same `init` module — `init` and
//! `rules update` are aliases that perform the same download +
//! verify + extract cycle, while `rules status` is a read-only inspect
//! of whatever the cache currently has.

use crate::cli_args::{InitArgs, OutputFormat, RulesStatusArgs, RulesUpdateArgs};
use crate::init;
use anyhow::{Context, Result};

pub(crate) fn run_init(args: InitArgs) -> Result<()> {
    let outcome = init::run_init(args.version, args.cache_dir)
        .context("`skill-veil init` failed; rules cache was NOT modified")?;
    println!(
        "skill-veil-rules {ver} installed ({files} files)\n  trusted key: {key}\n  install path: {path}",
        ver = outcome.version,
        files = outcome.file_count,
        key = outcome.trusted_key_id,
        path = outcome.install_dir.display(),
    );
    Ok(())
}

pub(crate) fn run_rules_update(args: RulesUpdateArgs) -> Result<()> {
    run_init(InitArgs {
        version: args.version,
        cache_dir: args.cache_dir,
    })
}

pub(crate) fn run_rules_status(args: RulesStatusArgs) -> Result<()> {
    let install =
        init::current_install(args.cache_dir).context("inspecting current rules install")?;
    match args.format {
        OutputFormat::Json => {
            let payload = serde_json::json!({
                "installed": install.as_ref().map(|i| serde_json::json!({
                    "version": i.version,
                    "trusted_key_id": i.trusted_key_id,
                    "install_dir": i.install_dir.display().to_string(),
                })),
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        OutputFormat::Text => match install {
            Some(i) => {
                println!(
                    "skill-veil-rules {ver}\n  trusted key: {key}\n  install path: {path}",
                    ver = i.version,
                    key = i.trusted_key_id,
                    path = i.install_dir.display(),
                );
            }
            None => {
                println!(
                    "no rules pack installed yet — run `skill-veil init` to download and verify the latest signed release"
                );
            }
        },
        OutputFormat::Sarif | OutputFormat::Shield => {
            anyhow::bail!("`rules status` only supports text or json output");
        }
    }
    Ok(())
}
