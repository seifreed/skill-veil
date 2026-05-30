use crate::color::ColorMode;
use crate::util::terminal_safe::sanitise_for_terminal;

/// Format `entry` as a single bullet for one of the diff sections.
/// `artifact_path` AND `reason` are attacker-controlled (both can carry
/// strings — e.g. artifact paths — that originate inside the scanned package),
/// so every field MUST go through `sanitise_for_terminal` before reaching the
/// TTY — matching the contract in `text.rs::append_findings`. Without this, a
/// malicious skill carrying a path like `evil-\x1b[2J\x1b[Hbenign.py` (which a
/// detector then interpolates into a finding's `reason`) could clear the
/// operator's terminal and repaint a forged verdict line when a CI run prints
/// the diff.
fn format_diff_entry(entry: &skill_veil_core::DiffEntry, color: ColorMode) -> String {
    let path = entry
        .artifact_path
        .as_deref()
        .map(sanitise_for_terminal)
        .unwrap_or_else(|| "-".to_string());
    format!(
        "  - {} {} {}\n",
        color.rule(sanitise_for_terminal(&entry.rule_id)),
        path,
        sanitise_for_terminal(&entry.reason)
    )
}

pub(crate) fn format_diff_text(diff: &skill_veil_core::DiffReport, color: ColorMode) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "{} Diff {}\n",
        color.heading("---"),
        color.heading("---")
    ));
    output.push_str(&format!(
        "New findings: {}\nResolved findings: {}\nWaived findings: {}\nBaselined findings: {}\nUnchanged findings: {}\n",
        diff.new_findings.len(),
        diff.resolved_findings.len(),
        diff.waived_findings.len(),
        diff.baselined_findings.len(),
        diff.unchanged_findings
    ));

    if !diff.new_findings.is_empty() {
        output.push_str("\nNew findings:\n");
        for entry in &diff.new_findings {
            output.push_str(&format_diff_entry(entry, color));
        }
    }

    if !diff.resolved_findings.is_empty() {
        output.push_str("\nResolved findings:\n");
        for entry in &diff.resolved_findings {
            output.push_str(&format_diff_entry(entry, color));
        }
    }

    if !diff.waived_findings.is_empty() {
        output.push_str("\nWaived findings:\n");
        for entry in &diff.waived_findings {
            output.push_str(&format_diff_entry(entry, color));
        }
    }

    if !diff.baselined_findings.is_empty() {
        output.push_str("\nBaselined findings:\n");
        for entry in &diff.baselined_findings {
            output.push_str(&format_diff_entry(entry, color));
        }
    }

    output
}

pub(crate) fn format_diff_ci_summary(diff: &skill_veil_core::DiffReport) -> String {
    format!(
        "DIFF new_active={} resolved={} waived={} baselined={} unchanged={}\n",
        diff.new_findings.len(),
        diff.resolved_findings.len(),
        diff.waived_findings.len(),
        diff.baselined_findings.len(),
        diff.unchanged_findings
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use skill_veil_core::{DiffEntry, DiffReport, ThreatCategory};

    fn entry_with_path(path: &str) -> DiffEntry {
        DiffEntry {
            fingerprint: "fp".into(),
            rule_id: "R".into(),
            category: ThreatCategory::SocialManipulation,
            artifact_path: Some(path.into()),
            reason: "static reason".into(),
        }
    }

    /// # Contract
    ///
    /// `format_diff_text` MUST run `artifact_path` through
    /// `sanitise_for_terminal` before emitting, matching the contract
    /// documented in `text.rs::append_findings` ("`match_value` and
    /// `artifact_path` come from the scanned package — attacker-controlled
    /// — and MUST be filtered before reaching the TTY"). Pre-fix the diff
    /// formatter dumped paths verbatim, so a malicious skill carrying a
    /// path like `evil-\x1b[2J\x1b[Hbenign.py` could clear the operator's
    /// terminal and repaint a forged verdict line in CI logs.
    #[test]
    fn format_diff_text_sanitises_attacker_controlled_artifact_path() {
        let diff = DiffReport {
            new_findings: vec![entry_with_path("evil-\x1b[2J\x1b[Hbenign.py")],
            resolved_findings: vec![entry_with_path("resolved-\x07.py")],
            waived_findings: vec![entry_with_path("waived-\x00.py")],
            baselined_findings: vec![entry_with_path("baselined-\x1b]8;;evil\x07.py")],
            unchanged_findings: 0,
        };

        let rendered = format_diff_text(
            &diff,
            ColorMode::from_choice(crate::cli_args::ColorChoiceArg::Never, false),
        );

        for raw in ['\x1b', '\x07', '\x00'] {
            assert!(
                !rendered.contains(raw),
                "diff output must not carry raw control byte {raw:?}; got:\n{rendered}",
            );
        }
        // The literal text around the controls survives — only the
        // control bytes themselves are replaced, so operators still see
        // the visible portion of the path.
        assert!(
            rendered.contains("evil-?[2J?[Hbenign.py"),
            "sanitised path must keep printable surroundings; got:\n{rendered}",
        );
    }

    /// # Contract
    ///
    /// `reason` and `rule_id` are attacker-controlled too — detectors
    /// interpolate package-internal artifact paths into `reason` — so the diff
    /// renderer MUST sanitise them, not only `artifact_path`.
    #[test]
    fn format_diff_text_sanitises_attacker_controlled_reason_and_rule_id() {
        let diff = DiffReport {
            new_findings: vec![DiffEntry {
                fingerprint: "fp".into(),
                rule_id: "R\x1b[31m".into(),
                category: ThreatCategory::SocialManipulation,
                artifact_path: Some("ok.py".into()),
                reason: "claims X but evil-\x1b[2J\x1b[Hbenign.py contradicts".into(),
            }],
            resolved_findings: vec![],
            waived_findings: vec![],
            baselined_findings: vec![],
            unchanged_findings: 0,
        };

        let rendered = format_diff_text(
            &diff,
            ColorMode::from_choice(crate::cli_args::ColorChoiceArg::Never, false),
        );

        assert!(
            !rendered.contains('\x1b'),
            "control bytes in reason/rule_id must be sanitised; got:\n{rendered}",
        );
        assert!(
            rendered.contains("evil-?[2J?[Hbenign.py contradicts"),
            "printable surroundings of reason must survive; got:\n{rendered}",
        );
    }

    /// # Contract
    ///
    /// Honest paths with no control bytes pass through verbatim. Pins
    /// the no-op branch so the sanitiser does not corrupt or lossily
    /// rewrite legitimate filenames (including dots, dashes, slashes,
    /// emoji-bearing folder names, etc.).
    #[test]
    fn format_diff_text_preserves_paths_without_control_bytes() {
        let diff = DiffReport {
            new_findings: vec![entry_with_path("scripts/helper.py")],
            resolved_findings: vec![],
            waived_findings: vec![],
            baselined_findings: vec![],
            unchanged_findings: 0,
        };
        let rendered = format_diff_text(
            &diff,
            ColorMode::from_choice(crate::cli_args::ColorChoiceArg::Never, false),
        );
        assert!(
            rendered.contains("scripts/helper.py"),
            "honest path must survive verbatim; got:\n{rendered}",
        );
    }
}
