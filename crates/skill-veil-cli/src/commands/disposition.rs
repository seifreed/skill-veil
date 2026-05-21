//! `disposition` — analyst feedback loop.
//!
//! Captures the analyst's real disposition of a finding into a
//! project-local overlay (NEVER the signed rule pack) and shows the
//! derived, bounded confidence adjustment / allowlist the scanner will
//! apply. Recording is append-only.

use std::path::Path;

use anyhow::{Context, Result};
use chrono::Utc;
use skill_veil_core::{
    learned_allowlist, learned_confidence_adjustments, Disposition, DispositionOverlay,
    DispositionRecord,
};

use crate::cli_args::{
    DispositionAction, DispositionListArgs, DispositionRecordArgs, DispositionStatsArgs,
    DispositionVerdictArg,
};
use crate::util::bounded_read::read_operator_text_file;
use crate::util::output_file::write_output_file_atomic;
use crate::util::terminal_safe::sanitise_for_terminal;

fn disposition_of(v: DispositionVerdictArg) -> Disposition {
    match v {
        DispositionVerdictArg::TruePositive => Disposition::TruePositive,
        DispositionVerdictArg::FalsePositive => Disposition::FalsePositive,
        DispositionVerdictArg::Benign => Disposition::Benign,
    }
}

fn load_overlay(path: &Path) -> Result<DispositionOverlay> {
    if !path.exists() {
        return Ok(DispositionOverlay::default());
    }
    let text = read_operator_text_file(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))
}

fn save_overlay(path: &Path, overlay: &DispositionOverlay) -> Result<()> {
    let json =
        serde_json::to_string_pretty(overlay).context("failed to serialise disposition overlay")?;
    write_output_file_atomic(path, json.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))
}

fn record(args: DispositionRecordArgs) -> Result<()> {
    let mut overlay = load_overlay(&args.file)?;
    overlay.records.push(DispositionRecord {
        finding_fingerprint: args.finding,
        rule_id: args.rule_id.clone(),
        sha256: args.sha256,
        analyst_disposition: disposition_of(args.verdict),
        recorded_at: Utc::now(),
        note: args.note,
    });
    save_overlay(&args.file, &overlay)?;
    println!(
        "recorded disposition for {} ({} total records)",
        terminal_text(&args.rule_id),
        overlay.records.len()
    );
    Ok(())
}

fn list(args: DispositionListArgs) -> Result<()> {
    let overlay = load_overlay(&args.file)?;
    for r in &overlay.records {
        if let Some(filter) = &args.rule_id {
            if &r.rule_id != filter {
                continue;
            }
        }
        println!(
            "{} {} {:?} {}",
            r.recorded_at.to_rfc3339(),
            terminal_text(&r.rule_id),
            r.analyst_disposition,
            terminal_text(&r.finding_fingerprint)
        );
    }
    Ok(())
}

fn stats(args: DispositionStatsArgs) -> Result<()> {
    let overlay = load_overlay(&args.file)?;
    let deltas = learned_confidence_adjustments(&overlay);
    let allowlist = learned_allowlist(&overlay);
    println!(
        "disposition overlay: {}",
        terminal_text(&args.file.display().to_string())
    );
    println!("  records: {}", overlay.records.len());
    if deltas.is_empty() {
        println!("  (no per-rule signal yet)");
        return Ok(());
    }
    println!("  per-rule (rule: Δconfidence [allowlisted?]):");
    for (rule, delta) in &deltas {
        let mark = if allowlist.contains(rule) {
            " [ALLOWLISTED → Log]"
        } else {
            ""
        };
        println!("    {}: {delta:+.4}{mark}", terminal_text(rule));
    }
    Ok(())
}

pub(crate) fn run_disposition(action: DispositionAction) -> Result<()> {
    match action {
        DispositionAction::Record(a) => record(a),
        DispositionAction::List(a) => list(a),
        DispositionAction::Stats(a) => stats(a),
    }
}

fn terminal_text(value: &str) -> String {
    sanitise_for_terminal(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Contract: record is append-only and round-trips through the
    /// overlay file; stats-relevant derivations stay consistent.
    #[test]
    fn record_appends_and_round_trips() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("nested").join("overlay.json");
        let mk = |v| DispositionRecordArgs {
            file: file.clone(),
            rule_id: "R1".to_string(),
            finding: "fp1".to_string(),
            sha256: None,
            verdict: v,
            note: None,
        };
        record(mk(DispositionVerdictArg::FalsePositive)).unwrap();
        record(mk(DispositionVerdictArg::FalsePositive)).unwrap();
        let overlay = load_overlay(&file).unwrap();
        assert_eq!(overlay.records.len(), 2, "record must be append-only");
        assert_eq!(overlay.records[0].rule_id, "R1");
    }

    /// Contract: a missing overlay file is an empty overlay, not an
    /// error (first-run ergonomics).
    #[test]
    fn missing_overlay_is_empty_not_error() {
        let dir = tempdir().unwrap();
        let overlay = load_overlay(&dir.path().join("absent.json")).unwrap();
        assert!(overlay.records.is_empty());
    }

    /// # Contract
    ///
    /// Saving a disposition overlay MUST replace a symlink at the final
    /// path without writing through to the symlink target.
    #[cfg(unix)]
    #[test]
    fn save_overlay_replaces_symlink_without_touching_target() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("outside.json");
        let link = dir.path().join("overlay.json");
        std::fs::write(&target, b"keep").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        save_overlay(&link, &DispositionOverlay::default()).unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        assert!(!std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    /// Contract: the verdict arg maps 1:1 to the core disposition.
    #[test]
    fn verdict_arg_maps_one_to_one() {
        assert_eq!(
            disposition_of(DispositionVerdictArg::TruePositive),
            Disposition::TruePositive
        );
        assert_eq!(
            disposition_of(DispositionVerdictArg::FalsePositive),
            Disposition::FalsePositive
        );
        assert_eq!(
            disposition_of(DispositionVerdictArg::Benign),
            Disposition::Benign
        );
    }

    #[test]
    fn terminal_text_removes_disposition_control_sequences() {
        let cleaned = terminal_text("RULE\x1b]8;;https://evil.invalid\x07click");

        assert!(!cleaned.contains('\x1b'));
        assert!(!cleaned.contains('\x07'));
    }
}
