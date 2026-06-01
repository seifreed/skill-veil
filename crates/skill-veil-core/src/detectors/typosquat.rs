//! Offline typosquatting detector for declared dependencies.
//!
//! Compares each declared dependency name against an embedded list of popular
//! package names for the same ecosystem. A name that is edit-distance 1 from a
//! popular name — but not equal to one under that ecosystem's canonical naming
//! rules — is flagged as a possible typosquat. Pure and offline; consumes the
//! [`ParsedDependency`](crate::dependency_inventory::ParsedDependency) set the
//! scanner already extracts from manifests.

use std::collections::HashSet;
use std::sync::OnceLock;

use crate::dependency_inventory::{Ecosystem, ParsedDependency};
use crate::detectors::native_ids::SUPPLY_CHAIN_TYPOSQUAT;
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};

const NPM_POPULAR: &str = include_str!("../../resources/typosquat/npm.txt");
const PYPI_POPULAR: &str = include_str!("../../resources/typosquat/pypi.txt");
const CRATES_POPULAR: &str = include_str!("../../resources/typosquat/crates.txt");

/// Names shorter than this are skipped: short names sit within edit-distance 1
/// of many unrelated packages, so flagging them is noise rather than signal.
const MIN_TYPOSQUAT_NAME_LEN: usize = 4;

const TYPOSQUAT_CONFIDENCE: f32 = 0.6;

/// Canonicalise a package name to the ecosystem's equality rules so that names
/// which the registry treats as identical are not mistaken for typosquats.
///
/// PyPI (PEP 503) folds runs of `-`, `_`, `.` to a single `-` and lowercases;
/// crates.io treats `-` and `_` as interchangeable; npm names are already
/// lowercase and separator-significant.
fn canonical(name: &str, ecosystem: Ecosystem) -> String {
    let lower = name.trim().to_ascii_lowercase();
    match ecosystem {
        Ecosystem::PyPI => {
            let mut out = String::with_capacity(lower.len());
            let mut prev_sep = false;
            for ch in lower.chars() {
                if matches!(ch, '-' | '_' | '.') {
                    if !prev_sep {
                        out.push('-');
                        prev_sep = true;
                    }
                } else {
                    out.push(ch);
                    prev_sep = false;
                }
            }
            out
        }
        Ecosystem::CratesIo => lower.replace('_', "-"),
        Ecosystem::Npm => lower,
    }
}

/// Established, distinct packages that happen to sit within edit-distance 1
/// of a popular name. They must NOT be flagged as typosquats. Kept separate
/// from the popular set so they are exempt WITHOUT themselves becoming squat
/// targets — adding them to the popular list would cascade new false
/// positives onto their own neighbours (e.g. `colour` vs `color`). Entries
/// are in canonical (lowercased) form for their ecosystem.
fn is_known_legitimate(canon: &str, ecosystem: Ecosystem) -> bool {
    let allowlist: &[&str] = match ecosystem {
        // `preact` is a distinct React-alternative framework (≠ `react`);
        // `color` is a distinct colour library (≠ `colors`).
        Ecosystem::Npm => &["preact", "color"],
        Ecosystem::PyPI => &[],
        Ecosystem::CratesIo => &[],
    };
    allowlist.contains(&canon)
}

fn popular_set(ecosystem: Ecosystem) -> &'static HashSet<String> {
    static NPM: OnceLock<HashSet<String>> = OnceLock::new();
    static PYPI: OnceLock<HashSet<String>> = OnceLock::new();
    static CRATES: OnceLock<HashSet<String>> = OnceLock::new();
    let (cell, raw) = match ecosystem {
        Ecosystem::Npm => (&NPM, NPM_POPULAR),
        Ecosystem::PyPI => (&PYPI, PYPI_POPULAR),
        Ecosystem::CratesIo => (&CRATES, CRATES_POPULAR),
    };
    cell.get_or_init(|| {
        raw.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| canonical(line, ecosystem))
            .collect()
    })
}

/// Optimal string alignment (Damerau-Levenshtein with adjacent transpositions),
/// returning `true` only when the distance is exactly 1. Returns `false` for
/// equal strings and for distance ≥ 2.
fn is_edit_distance_one(a: &str, b: &str) -> bool {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (la, lb) = (a.len(), b.len());
    if la.abs_diff(lb) > 1 {
        return false;
    }
    let mut prev_prev = vec![0usize; lb + 1];
    let mut prev = (0..=lb).collect::<Vec<usize>>();
    for i in 1..=la {
        let mut curr = vec![0usize; lb + 1];
        curr[0] = i;
        for j in 1..=lb {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(prev_prev[j - 2] + 1);
            }
            curr[j] = best;
        }
        prev_prev = prev;
        prev = curr;
    }
    prev[lb] == 1
}

/// Scan the declared dependencies for names that closely resemble popular
/// packages. Each finding attributes itself to the dependency's source manifest.
pub(crate) fn scan_typosquat(deps: &[ParsedDependency]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    for dep in deps {
        let canon = canonical(&dep.name, dep.ecosystem);
        if canon.chars().count() < MIN_TYPOSQUAT_NAME_LEN {
            continue;
        }
        let popular = popular_set(dep.ecosystem);
        if popular.contains(&canon) || is_known_legitimate(&canon, dep.ecosystem) {
            continue;
        }
        let Some(target) = find_typosquat_target(&canon, popular) else {
            continue;
        };
        if !seen.insert((dep.ecosystem, canon.clone(), target.clone())) {
            continue;
        }
        findings.push(build_finding(dep, target));
    }
    findings
}

/// Pick the popular name a candidate typosquats. A name can be
/// edit-distance 1 from several popular names at once; selecting the
/// lexicographically smallest makes the emitted finding reproducible
/// across runs — `HashSet` iteration order is per-process randomised,
/// so `iter().find(..)` would otherwise vary the reported target (and
/// thus the finding's `match_value` / `reason` text) run to run.
fn find_typosquat_target<'a>(canon: &str, popular: &'a HashSet<String>) -> Option<&'a String> {
    popular
        .iter()
        .filter(|name| is_edit_distance_one(canon, name))
        .min()
}

fn build_finding(dep: &ParsedDependency, target: &str) -> Finding {
    Finding::builder(SUPPLY_CHAIN_TYPOSQUAT, ThreatCategory::SupplyChain)
        .severity(Severity::Medium)
        .confidence(TYPOSQUAT_CONFIDENCE)
        .action(RecommendedAction::RequireApproval)
        .evidence_kind(EvidenceKind::Behavior)
        .artifact(
            ArtifactKind::PackageManifest,
            Some(dep.source_artifact.clone()),
        )
        .matched_on(MatchTarget::ReferencedFile {
            path: dep.source_artifact.clone(),
        })
        .match_value(format!(
            "{} ~ {} ({})",
            dep.name,
            target,
            dep.ecosystem.osv_name()
        ))
        .reason(format!(
            "Dependency '{}' is one edit away from the popular {} package '{}'; possible typosquat",
            dep.name,
            dep.ecosystem.osv_name(),
            target
        ))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(name: &str, ecosystem: Ecosystem) -> ParsedDependency {
        ParsedDependency {
            name: name.to_string(),
            version: None,
            ecosystem,
            source_artifact: "package.json".to_string(),
        }
    }

    fn rule_ids(deps: &[ParsedDependency]) -> Vec<String> {
        scan_typosquat(deps)
            .into_iter()
            .map(|f| f.rule_id)
            .collect()
    }

    #[test]
    fn near_miss_of_popular_name_fires() {
        let found = scan_typosquat(&[dep("reqeusts", Ecosystem::PyPI)]);
        assert_eq!(found.len(), 1, "transposition typo of 'requests' must fire");
        assert_eq!(found[0].rule_id, SUPPLY_CHAIN_TYPOSQUAT);
        assert_eq!(found[0].category, ThreatCategory::SupplyChain);
    }

    #[test]
    fn exact_popular_name_does_not_fire() {
        assert!(rule_ids(&[dep("requests", Ecosystem::PyPI)]).is_empty());
        assert!(rule_ids(&[dep("lodash", Ecosystem::Npm)]).is_empty());
        assert!(rule_ids(&[dep("serde", Ecosystem::CratesIo)]).is_empty());
    }

    /// Contract: an established, distinct package that happens to be one
    /// edit away from a popular name (`preact` vs `react`, `color` vs
    /// `colors`) is NOT a typosquat. Pre-fix the pure distance-1 rule
    /// flagged these legitimate, widely-used packages with RequireApproval.
    /// A genuine near-miss typo still fires.
    #[test]
    fn known_legitimate_neighbors_do_not_fire() {
        assert!(rule_ids(&[dep("preact", Ecosystem::Npm)]).is_empty());
        assert!(rule_ids(&[dep("color", Ecosystem::Npm)]).is_empty());
        // A genuine typo of a popular package still fires.
        assert_eq!(rule_ids(&[dep("raect", Ecosystem::Npm)]).len(), 1);
    }

    #[test]
    fn pypi_separator_equivalent_is_not_a_typosquat() {
        // PEP 503 treats these as the SAME package as `python-dateutil`.
        assert!(rule_ids(&[dep("python_dateutil", Ecosystem::PyPI)]).is_empty());
        assert!(rule_ids(&[dep("python.dateutil", Ecosystem::PyPI)]).is_empty());
    }

    #[test]
    fn short_names_are_skipped() {
        // `ws` is itself popular; a 3-char near-miss like `wss` must stay silent.
        assert!(rule_ids(&[dep("wss", Ecosystem::Npm)]).is_empty());
    }

    #[test]
    fn ecosystem_is_isolated() {
        // `lodash` is an npm name; a near-miss declared as a PyPI dep must not
        // match the npm popularity list.
        assert!(rule_ids(&[dep("lodahs", Ecosystem::PyPI)]).is_empty());
        assert_eq!(rule_ids(&[dep("lodahs", Ecosystem::Npm)]).len(), 1);
    }

    #[test]
    fn distant_name_does_not_fire() {
        assert!(rule_ids(&[dep("my-internal-helper", Ecosystem::Npm)]).is_empty());
    }

    /// Contract: when a candidate is edit-distance 1 from MORE THAN ONE
    /// popular name, the reported target is the lexicographically
    /// smallest match — deterministic regardless of `HashSet` iteration
    /// order, so the finding text is byte-identical across runs.
    #[test]
    fn typosquat_target_selection_is_deterministic() {
        let mut popular = HashSet::new();
        popular.insert("requests".to_string());
        popular.insert("requestx".to_string());

        // `requestz` is one substitution from both candidates.
        let target = find_typosquat_target("requestz", &popular);

        assert_eq!(
            target.map(String::as_str),
            Some("requests"),
            "must deterministically pick the lexicographically smallest match"
        );
    }

    /// Contract (negative): a candidate equidistant from none of the
    /// popular names yields no target.
    #[test]
    fn typosquat_target_absent_when_no_match() {
        let mut popular = HashSet::new();
        popular.insert("requests".to_string());

        assert!(find_typosquat_target("totally-different", &popular).is_none());
    }

    #[test]
    fn edit_distance_one_detects_each_single_edit() {
        assert!(is_edit_distance_one("requests", "reqests")); // deletion
        assert!(is_edit_distance_one("requests", "requeests")); // insertion
        assert!(is_edit_distance_one("requests", "reqursts")); // substitution
        assert!(is_edit_distance_one("requests", "reqeusts")); // transposition
        assert!(!is_edit_distance_one("requests", "requests")); // equal
        assert!(!is_edit_distance_one("requests", "reqst")); // distance 3
    }
}
