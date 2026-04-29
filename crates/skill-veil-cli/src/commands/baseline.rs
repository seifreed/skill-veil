use crate::cli_args::{BaselineCreateArgs, BaselineUpdateArgs};
use anyhow::{Context, Result};
use skill_veil_core::{
    baseline_from_reports, load_baseline, BaselineEntry, BaselineFile, StdFileSystemProvider,
    POLICY_SCHEMA_VERSION,
};
use std::collections::BTreeMap;

pub(crate) fn run_baseline_create(args: BaselineCreateArgs) -> Result<()> {
    let reports = super::policy::load_json_reports(&args.report)?;
    let baseline = baseline_from_reports(&reports);
    let content =
        serde_json::to_string_pretty(&baseline).context("Failed to serialize baseline")?;
    std::fs::write(&args.output, content).context("Failed to write baseline file")?;
    Ok(())
}

pub(crate) fn run_baseline_update(args: BaselineUpdateArgs) -> Result<()> {
    let reports = super::policy::load_json_reports(&args.report)?;
    let fs = StdFileSystemProvider::new();
    let existing = load_baseline(&fs, &args.baseline).context("Failed to load baseline file")?;
    let current = baseline_from_reports(&reports);

    let existing_map: BTreeMap<_, _> = existing
        .entries
        .into_iter()
        .map(|entry| (entry.fingerprint.clone(), entry))
        .collect();
    let current_map: BTreeMap<_, _> = current
        .entries
        .into_iter()
        .map(|entry| (entry.fingerprint.clone(), entry))
        .collect();

    let new_entries: Vec<_> = current_map
        .iter()
        .filter(|(fingerprint, _)| !existing_map.contains_key(*fingerprint))
        .map(|(_, entry)| entry.clone())
        .collect();

    if !new_entries.is_empty() && !args.allow_new_findings {
        anyhow::bail!(
            "Baseline update would add {} new finding(s). Re-run with --allow-new-findings to accept them.",
            new_entries.len()
        );
    }

    let mut merged_map = existing_map;
    for (fingerprint, entry) in current_map {
        merged_map.insert(fingerprint, entry);
    }
    let merged_entries: Vec<BaselineEntry> = merged_map.into_values().collect();
    let updated = BaselineFile {
        schema_version: POLICY_SCHEMA_VERSION.to_string(),
        entries: merged_entries,
    };
    let content =
        serde_json::to_string_pretty(&updated).context("Failed to serialize updated baseline")?;
    std::fs::write(&args.output, content).context("Failed to write updated baseline file")?;
    Ok(())
}
