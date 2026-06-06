//! Supply-chain detectors that examine package-install commands. The
//! current detector targets typosquatted global installs of agent assets.

use crate::findings::{Finding, RecommendedAction, Severity, ThreatCategory};
use crate::lazy_pattern;

use super::match_helpers::referenced_artifact_behavior_finding;

// Bounded-whitespace install pattern. The pre-fix shape
// `(?:-g\s+|--global\s+|--force\s+)+` paired `\s+` (which devours
// newlines across statements) with an outer `+` quantifier, producing
// catastrophic backtracking on large scripts (>=40 min for the 3k-sample
// VT corpus). `[ \t]+` keeps matching on a single line.
//
// `npx <pkg>` downloads and runs a package directly and never takes a
// `-g`/`--global` flag, so it is a separate flagless alternative — pairing
// it with the mandatory global-install flag (as the pre-fix pattern did)
// made `npx <typosquat>` structurally unreachable, letting the highest-risk
// remote-execution form evade the typosquat backstop. `npx` is not the only
// flagless download-and-run launcher: `bunx`, `pnpm dlx`, `yarn dlx`,
// `pipx run`, and `uvx` fetch and execute a package by name with no install
// flag, so each is an equivalent typosquat vector and shares the flagless
// arm. The other commands keep the global-flag requirement; the
// Levenshtein-distance gate below prevents the flagless arms from firing on
// legitimate package names.
lazy_pattern!(
    INSTALL_RE,
    r"(?i)\b(?:(?:npm[ \t]+install|npm[ \t]+i\b|yarn[ \t]+add|pnpm[ \t]+add|clawhub[ \t]+install|clauhub[ \t]+install)[ \t]+(?:-g|--global|--force)[ \t]+|(?:npx|bunx|pnpm[ \t]+dlx|yarn[ \t]+dlx|pipx[ \t]+run|uvx)[ \t]+)([a-z][a-z0-9_.-]{2,40})"
);

const TYPOSQUAT_KNOWN_GOOD: &[&str] = &[
    "sher",
    "human-test",
    "clawion",
    "openclaw",
    "claude",
    "openclaw-cli",
    "openclaw-skills",
];

/// Levenshtein distance with a small early-out cap. Returns `cap` when the
/// distance is known to exceed `cap`, otherwise the exact value.
fn levenshtein_capped(a: &str, b: &str, cap: usize) -> usize {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len().abs_diff(b_bytes.len()) > cap {
        return cap + 1;
    }
    let mut prev: Vec<usize> = (0..=b_bytes.len()).collect();
    let mut cur: Vec<usize> = vec![0; b_bytes.len() + 1];
    for (i, ca) in a_bytes.iter().enumerate() {
        cur[0] = i + 1;
        let mut row_min = cur[0];
        for (j, cb) in b_bytes.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
            if cur[j + 1] < row_min {
                row_min = cur[j + 1];
            }
        }
        if row_min > cap {
            return cap + 1;
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b_bytes.len()]
}

/// Detect global package installs whose name looks like (Levenshtein 1-2
/// off) a known-good agent asset. Backstop for the YAML rule
/// `SKILL_SUPPLY_CHAIN_TYPOSQUATTING`, which only matches a hardcoded
/// allow-list. This detector generalises to any new typo.
pub(crate) fn detect_typosquatted_install(
    content_lower: &str,
    _language: &str,
    artifact_path: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for cap in INSTALL_RE.captures_iter(content_lower) {
        let Some(name) = cap.get(1).map(|m| m.matched_text.as_str()) else {
            continue;
        };
        for expected in TYPOSQUAT_KNOWN_GOOD {
            let dist = levenshtein_capped(name, expected, 2);
            if (1..=2).contains(&dist) {
                findings.push(referenced_artifact_behavior_finding(
                    "SCRIPT_SUPPLY_CHAIN_TYPOSQUAT",
                    ThreatCategory::SupplyChain,
                    Severity::Critical,
                    RecommendedAction::Block,
                    artifact_path,
                    format!("{name} ≈ {expected} (lev={dist})"),
                    "Globally installed package name is 1-2 characters off a known agent asset — typosquat",
                ));
                break;
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Contract
    ///
    /// `detect_typosquatted_install` MUST fire on Levenshtein-1 typos of
    /// `sher`/`openclaw`/`claude` installed globally. Pinned against
    /// VT corpus SHA `27d66e68` (sher-deploy installs `shersh`).
    #[test]
    fn detect_typosquatted_install_fires_on_shersh() {
        let script = "npm install -g shersh\n";
        let lower = script.to_ascii_lowercase();
        let findings = detect_typosquatted_install(&lower, "sh", "/tmp/install.sh");
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "SCRIPT_SUPPLY_CHAIN_TYPOSQUAT"),
            "expected SCRIPT_SUPPLY_CHAIN_TYPOSQUAT, got {findings:?}"
        );
    }

    /// # Contract
    ///
    /// `npx <typosquat>` (flagless remote execution) MUST fire. Pre-fix the
    /// mandatory global-install flag after every command made the `npx` arm
    /// structurally unreachable, so `npx shersh` — the highest-risk
    /// download-and-run form — evaded the typosquat backstop. A legitimate
    /// flagless `npx <good-pkg>` still does not fire (distance gate).
    #[test]
    fn detect_typosquatted_install_fires_on_flagless_npx() {
        let lower = "npx shersh\n".to_ascii_lowercase();
        let findings = detect_typosquatted_install(&lower, "sh", "/tmp/x.sh");
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "SCRIPT_SUPPLY_CHAIN_TYPOSQUAT"),
            "npx typosquat must fire, got {findings:?}"
        );
        let benign = "npx create-react-app myapp\n".to_ascii_lowercase();
        assert!(
            detect_typosquatted_install(&benign, "sh", "/tmp/x.sh").is_empty(),
            "a legitimate flagless npx must not fire",
        );
    }

    /// # Contract
    ///
    /// Every flagless download-and-run launcher is a typosquat vector, not
    /// just `npx`. `bunx`, `pnpm dlx`, `yarn dlx`, `pipx run`, and `uvx`
    /// fetch and execute a package by name with no install flag, so a
    /// typosquatted name under any of them MUST fire. A legitimate package
    /// name under the same launcher MUST NOT fire (distance gate).
    #[test]
    fn detect_typosquatted_install_fires_on_all_flagless_launchers() {
        for launcher in ["bunx", "pnpm dlx", "yarn dlx", "pipx run", "uvx"] {
            let lower = format!("{launcher} shersh\n").to_ascii_lowercase();
            assert!(
                detect_typosquatted_install(&lower, "sh", "/tmp/x.sh")
                    .iter()
                    .any(|f| f.rule_id == "SCRIPT_SUPPLY_CHAIN_TYPOSQUAT"),
                "typosquat under `{launcher}` must fire",
            );
            let benign = format!("{launcher} create-react-app myapp\n").to_ascii_lowercase();
            assert!(
                detect_typosquatted_install(&benign, "sh", "/tmp/x.sh").is_empty(),
                "a legitimate package under `{launcher}` must not fire",
            );
        }
    }

    /// # Contract
    ///
    /// Package-manager command phrases accept tabs between command words.
    #[test]
    fn detect_typosquatted_install_accepts_tab_separated_command_phrase() {
        let script = "npm\tinstall -g shersh\nclawhub\tinstall --force openclaaw\n";
        let lower = script.to_ascii_lowercase();
        let findings = detect_typosquatted_install(&lower, "sh", "/tmp/install.sh");
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.rule_id == "SCRIPT_SUPPLY_CHAIN_TYPOSQUAT")
                .count(),
            2
        );
    }

    /// # Contract (negative)
    ///
    /// Legitimate global install names (`typescript`, `prettier`) MUST
    /// NOT be flagged as typosquats — Levenshtein distance to known
    /// agent assets is well above the cap.
    #[test]
    fn detect_typosquatted_install_does_not_fire_on_typescript() {
        let script = "npm install -g typescript\n";
        let lower = script.to_ascii_lowercase();
        let findings = detect_typosquatted_install(&lower, "sh", "/tmp/x.sh");
        assert!(
            findings.is_empty(),
            "MUST NOT fire on `typescript`; got {findings:?}"
        );
    }
}
