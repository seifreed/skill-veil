//! Render the OSV advisory block. All provider-supplied strings pass through
//! the terminal sanitiser before reaching the operator's TTY, matching the VT
//! enrichment formatter.

use super::types::{DependencyAdvisories, ResolvedAdvisory};
use crate::util::terminal_safe::sanitise_for_terminal;
use std::fmt::Write as _;

/// Characters of an advisory summary retained in the block.
const SUMMARY_MAX_CHARS: usize = 140;

pub(super) fn render(
    advisories: &[DependencyAdvisories],
    queried: usize,
    skipped: usize,
) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "\n=== OSV.dev CVE Lookup (informational; does not affect skill-veil verdict) ==="
    );
    let total_advisories: usize = advisories.iter().map(|d| d.advisories.len()).sum();
    let _ = writeln!(
        out,
        "  queried {queried} pinned dependenc{} ({skipped} skipped: no exact version); \
         {} with advisories, {total_advisories} advisor{} total",
        if queried == 1 { "y" } else { "ies" },
        advisories.len(),
        if total_advisories == 1 { "y" } else { "ies" },
    );

    for dep in advisories {
        let _ = writeln!(
            out,
            "\n  {}@{} ({}): {} advisor{}",
            sanitise_for_terminal(&dep.name),
            sanitise_for_terminal(&dep.version),
            dep.ecosystem.osv_name(),
            dep.advisories.len(),
            if dep.advisories.len() == 1 {
                "y"
            } else {
                "ies"
            },
        );
        for adv in &dep.advisories {
            let _ = writeln!(out, "    - {}", format_advisory(adv));
        }
    }
    out
}

fn format_advisory(adv: &ResolvedAdvisory) -> String {
    let id = sanitise_for_terminal(&adv.id);
    let aliases = if adv.aliases.is_empty() {
        String::new()
    } else {
        let joined = adv
            .aliases
            .iter()
            .map(|a| sanitise_for_terminal(a))
            .collect::<Vec<_>>()
            .join(", ");
        format!(" [{joined}]")
    };
    let severity = adv
        .severity
        .as_ref()
        .map(|s| format!(" {}", sanitise_for_terminal(s)))
        .unwrap_or_default();
    let summary = adv
        .summary
        .as_ref()
        .map(|s| {
            let truncated: String = s.chars().take(SUMMARY_MAX_CHARS).collect();
            format!(" — {}", sanitise_for_terminal(&truncated))
        })
        .unwrap_or_default();
    format!("{id}{aliases}{severity}{summary}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use skill_veil_core::Ecosystem;

    #[test]
    fn render_lists_dependency_and_advisory() {
        let advisories = vec![DependencyAdvisories {
            name: "requests".to_string(),
            version: "2.19.0".to_string(),
            ecosystem: Ecosystem::PyPI,
            advisories: vec![ResolvedAdvisory {
                id: "GHSA-x".to_string(),
                aliases: vec!["CVE-2018-18074".to_string()],
                summary: Some("Credentials leak on redirect".to_string()),
                severity: Some("CVSS_V3:7.5".to_string()),
            }],
        }];
        let out = render(&advisories, 3, 1);
        assert!(out.contains("requests@2.19.0 (PyPI)"));
        assert!(out.contains("GHSA-x"));
        assert!(out.contains("CVE-2018-18074"));
        assert!(out.contains("CVSS_V3:7.5"));
        assert!(out.contains("does not affect skill-veil verdict"));
        assert!(out.contains("1 skipped"));
    }

    #[test]
    fn render_sanitises_control_bytes_from_advisory_strings() {
        let advisories = vec![DependencyAdvisories {
            name: "pkg".to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Ecosystem::Npm,
            advisories: vec![ResolvedAdvisory {
                id: "GHSA-y\x1b[2J".to_string(),
                aliases: vec!["CVE-x\x07".to_string()],
                summary: Some("boom\x1b[31m".to_string()),
                severity: None,
            }],
        }];
        let out = render(&advisories, 1, 0);
        assert!(!out.contains('\x1b'), "ESC must be sanitised");
        assert!(!out.contains('\x07'), "BEL must be sanitised");
    }
}
