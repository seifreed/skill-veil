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
    match &outcome.nova {
        Some(n) => {
            println!(
                "nova-rules {sha} installed ({files} .nov files)\n  install path: {path}",
                sha = short_sha(&n.commit_sha),
                files = n.file_count,
                path = n.install_dir.display(),
            );
        }
        None => {
            eprintln!(
                "warning: NOVA install was skipped (network or upstream error). \
                 Re-run `skill-veil rules update` to retry."
            );
        }
    }
    Ok(())
}

fn short_sha(sha: &str) -> &str {
    if sha.len() >= 7 {
        &sha[..7]
    } else {
        sha
    }
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
                "skill_veil_rules": install.skill_veil.as_ref().map(|i| serde_json::json!({
                    "version": i.version,
                    "trusted_key_id": i.trusted_key_id,
                    "install_dir": i.install_dir.display().to_string(),
                })),
                "nova_rules": install.nova.as_ref().map(|n| serde_json::json!({
                    "commit_sha": n.commit_sha,
                    "tarball_sha256": n.tarball_sha256,
                    "install_dir": n.install_dir.display().to_string(),
                    "file_count": n.file_count,
                })),
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        OutputFormat::Text => {
            match &install.skill_veil {
                Some(i) => println!(
                    "skill-veil-rules {ver}\n  trusted key: {key}\n  install path: {path}",
                    ver = i.version,
                    key = i.trusted_key_id,
                    path = i.install_dir.display(),
                ),
                None => println!(
                    "skill-veil-rules: NOT INSTALLED — run `skill-veil init` to download the latest signed release"
                ),
            }
            match &install.nova {
                Some(n) => println!(
                    "nova-rules {short}\n  tarball sha256: {sha}\n  files: {files} .nov files\n  install path: {path}",
                    short = short_sha(&n.commit_sha),
                    sha = n.tarball_sha256,
                    files = n.file_count,
                    path = n.install_dir.display(),
                ),
                None => println!(
                    "nova-rules: NOT INSTALLED — run `skill-veil rules update` to fetch from github.com/Nova-Hunting/nova-rules"
                ),
            }
        }
        OutputFormat::Sarif | OutputFormat::Shield => {
            anyhow::bail!("`rules status` only supports text or json output");
        }
    }
    Ok(())
}
