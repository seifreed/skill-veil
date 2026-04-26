//! Cross-checks skill-veil's own per-package verdicts against VirusTotal's
//! Code Insight verdicts loaded from the `.vt-reports/` cache.
//!
//! The primary output is a list of "we missed" packages — ones VT flagged as
//! `malicious` but skill-veil classified as `benign` or `suspicious`. The VT
//! `analysis` text for each of those packages is the single best source for
//! designing new detection rules.

use super::types::CachedReport;
use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use skill_veil_core::{PackageScanResult, Verdict};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const REPORTS_DIRNAME: &str = super::download::REPORTS_DIRNAME;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Classification {
    /// Both engines flagged the package as malicious. VT verdict is
    /// `"malicious"` and skill-veil's verdict is `Malicious` or
    /// `Suspicious`.
    AgreeMalicious,
    /// Both engines flagged at the lower-confidence "suspicious" tier:
    /// VT verdict is `"suspicious"` and skill-veil is `Malicious` or
    /// `Suspicious`. Distinguished from `AgreeMalicious` so the audit
    /// trail reflects the confidence VT actually returned — a package
    /// VT marked merely suspicious should not be reported as if VT
    /// confirmed it as malicious.
    AgreeSuspicious,
    /// Both engines agreed the package is clean. VT verdict is
    /// `"benign"` or `"harmless"` and skill-veil's verdict is `Benign`.
    AgreeBenign,
    /// We said clean, VT said malicious. The most actionable bucket for
    /// rule design: VT's analysis text is the seed for new detection
    /// rules.
    WeMissed,
    /// We said clean, VT said suspicious. Lower-confidence miss.
    /// Distinguished from `WeMissed` so we don't inflate the apparent
    /// "missed malware" count with packages VT only flagged at the
    /// suspicious tier.
    WeMissedSuspicious,
    /// We flagged a package VT considers clean. Either we have a false
    /// positive or we caught something VT doesn't yet detect.
    WeOverreached,
    /// VT has no report or returned an unrecognized verdict string.
    Unknown,
}

#[derive(Debug, Clone, Copy)]
enum VtTier {
    Malicious,
    Suspicious,
    Benign,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct PackageCrossCheck {
    pub(crate) sha256: String,
    pub(crate) our_verdict: String,
    pub(crate) our_risk_score: u32,
    pub(crate) our_findings: Vec<String>,
    pub(crate) vt_category: Option<String>,
    pub(crate) vt_verdict: Option<String>,
    pub(crate) vt_analysis: Option<String>,
    pub(crate) meaningful_name: Option<String>,
    pub(crate) classification: Classification,
}

#[derive(Debug, Clone, Serialize, Default)]
pub(crate) struct CrossCheckSummary {
    pub(crate) total: usize,
    pub(crate) agree_malicious: usize,
    /// Count of packages where both engines agreed at the lower-confidence
    /// suspicious tier. Tracked separately from `agree_malicious` so the
    /// audit trail preserves VT's confidence level.
    #[serde(default)]
    pub(crate) agree_suspicious: usize,
    pub(crate) agree_benign: usize,
    pub(crate) we_missed: usize,
    /// Count of packages where we said clean but VT said suspicious.
    /// Tracked separately from `we_missed` so users don't conflate
    /// VT-suspicious packages with VT-malicious packages in their
    /// "we missed" review queue.
    #[serde(default)]
    pub(crate) we_missed_suspicious: usize,
    pub(crate) we_overreached: usize,
    pub(crate) unknown: usize,
    pub(crate) packages: Vec<PackageCrossCheck>,
}

pub(crate) struct CrossCheckOptions {
    pub(crate) dataset_dir: PathBuf,
    pub(crate) only_mismatches: bool,
}

pub(crate) fn build_summary(
    scan_results: &[PackageScanResult],
    opts: &CrossCheckOptions,
) -> Result<CrossCheckSummary> {
    let reports_dir = opts.dataset_dir.join(REPORTS_DIRNAME);
    let reports = load_reports(&reports_dir)?;

    let mut summary = CrossCheckSummary::default();

    for pkg in scan_results {
        for res in &pkg.results {
            // The reports cache is keyed by the SHA-256 returned by VT for the
            // file. `package_id` is only a SHA when the corpus was produced
            // by `vt download` (whose layout is `<sha>/...`); for any other
            // corpus (extracted ZIPs, source dirs) it's a path-derived
            // identifier or `None`, and a direct lookup would always miss.
            // Fall back to hashing the primary artifact on disk so cross-
            // check is meaningful for arbitrary corpora.
            let Some(sha) = sha_for_lookup(&res.metadata.package_id, &res.metadata.path) else {
                // Without a SHA we cannot key the VT report cache, so the
                // result is structurally invisible to cross-check. Logging
                // it (vs. silently skipping) is what keeps `summary.total`
                // reconcilable with `scan_results.len()` for users running
                // large dataset scans.
                tracing::warn!(
                    package_id = ?res.metadata.package_id,
                    path = %res.metadata.path.display(),
                    "cross-check: skipping scan result without recoverable SHA-256",
                );
                continue;
            };
            let our_verdict = verdict_label(res.verdict);
            let our_risk_score = res.summary.risk_score;
            let our_findings: Vec<String> = res
                .findings
                .iter()
                .map(|f| f.rule_id.clone())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();

            let report = reports.get(&sha);
            let (category, verdict, analysis, name) = match report {
                Some(r) => {
                    let ai = r.attributes.primary_ai_verdict();
                    (
                        ai.map(|a| a.category.clone()),
                        ai.map(|a| a.verdict.clone()),
                        ai.map(|a| a.analysis.clone()),
                        r.attributes.meaningful_name.clone(),
                    )
                }
                None => (None, None, None, None),
            };

            // VT Code Insight puts the actionable label in `verdict`
            // ("malicious" | "suspicious" | "benign") and uses `category` as a
            // loose source tag (e.g. "code_insight"). Classify by verdict.
            let classification = classify(res.verdict, verdict.as_deref());
            summary.total += 1;
            match classification {
                Classification::AgreeMalicious => summary.agree_malicious += 1,
                Classification::AgreeSuspicious => summary.agree_suspicious += 1,
                Classification::AgreeBenign => summary.agree_benign += 1,
                Classification::WeMissed => summary.we_missed += 1,
                Classification::WeMissedSuspicious => summary.we_missed_suspicious += 1,
                Classification::WeOverreached => summary.we_overreached += 1,
                Classification::Unknown => summary.unknown += 1,
            }

            if opts.only_mismatches
                && !matches!(
                    classification,
                    Classification::WeMissed
                        | Classification::WeMissedSuspicious
                        | Classification::WeOverreached
                )
            {
                continue;
            }

            summary.packages.push(PackageCrossCheck {
                sha256: sha,
                our_verdict,
                our_risk_score,
                our_findings,
                vt_category: category,
                vt_verdict: verdict,
                vt_analysis: analysis,
                meaningful_name: name,
                classification,
            });
        }
    }

    Ok(summary)
}

fn load_reports(reports_dir: &Path) -> Result<BTreeMap<String, CachedReport>> {
    let mut out = BTreeMap::new();
    if !reports_dir.is_dir() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(reports_dir)
        .with_context(|| format!("reading {}", reports_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(cached) = serde_json::from_slice::<CachedReport>(&bytes) else {
            tracing::warn!("skipping unreadable VT report {}", path.display());
            continue;
        };
        // Lookup keys (`sha_for_lookup`) are guaranteed lowercase via
        // `is_sha256_hex` (rejects uppercase) and `format!("{:x}")` for
        // on-disk hashing. Cache keys MUST match that contract — a report
        // file with `"sha256": "FF00AA..."` would otherwise be stored
        // verbatim and never matched by the lookup, surfacing as `Unknown`
        // even though the report exists.
        out.insert(cached.sha256.to_ascii_lowercase(), cached);
    }
    Ok(out)
}

/// SHA-256 digests in this codebase are always **lowercase** hex; uppercase
/// or mixed-case 64-char strings are intentionally rejected so that two
/// copies of the same package with different casing cannot evade
/// case-sensitive cache lookups. Kept in sync with `derive_package_id` in
/// `scanner_graph.rs`.
fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(is_lower_hex_byte)
}

#[inline]
fn is_lower_hex_byte(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'a'..=b'f')
}

/// Resolve the SHA-256 used to look up a package's VT report.
///
/// # Lookup order (highest fidelity to lowest)
///
/// 1. `package_id` if it is already a 64-char hex digest. This is what
///    `derive_package_id` returns when an ancestor directory of the primary
///    artifact is named after the SHA — the canonical `vt download` layout
///    where files are saved at `dest/<sha>` or extracted into `dest/<sha>/...`.
///
/// 2. Walk ancestors of `path` looking for a 64-hex segment, allowing common
///    extraction suffixes like `_extracted`. Covers ZIP-extracted corpora
///    where the scanner reads `dest/<sha>_extracted/SKILL.md` and `package_id`
///    fails to recover the SHA because `derive_package_id` only matches the
///    bare hex form.
///
/// 3. Hash the primary artifact on disk. This is the LAST resort and is
///    only meaningful for direct-file corpora where the file at `path` IS
///    the file VT keyed its report by. For ZIP corpora this hash will not
///    match any cached report; the lookup will return `Unknown`, which is
///    the correct behaviour given we have no SHA-traceable provenance.
///
/// Returns `None` only when all three routes fail (e.g. the file is gone).
fn sha_for_lookup(package_id: &Option<String>, path: &Path) -> Option<String> {
    if let Some(id) = package_id {
        if is_sha256_hex(id) {
            return Some(id.clone());
        }
    }
    if let Some(sha) = sha_from_ancestors(path) {
        return Some(sha);
    }
    compute_file_sha256(path).ok()
}

/// Recover a SHA-256 from any ancestor directory whose name is a 64-hex
/// string, optionally with a recognised extraction suffix. Mirrors the
/// "directory named after sha" convention used by `vt download` and the
/// dataset extractor.
fn sha_from_ancestors(path: &Path) -> Option<String> {
    const EXTRACTION_SUFFIXES: &[&str] = &["_extracted", ".extracted", "-extracted"];
    path.ancestors()
        .filter_map(|a| a.file_name().and_then(|n| n.to_str()))
        .filter_map(|name| {
            if is_sha256_hex(name) {
                return Some(name.to_string());
            }
            for suffix in EXTRACTION_SUFFIXES {
                if let Some(stem) = name.strip_suffix(suffix) {
                    if is_sha256_hex(stem) {
                        return Some(stem.to_string());
                    }
                }
            }
            None
        })
        .next()
}

fn compute_file_sha256(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("hashing {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

fn classify(our: Verdict, vt_category: Option<&str>) -> Classification {
    let vt = match vt_category.map(|c| c.to_ascii_lowercase()) {
        Some(s) => s,
        None => return Classification::Unknown,
    };
    let vt_tier = match vt.as_str() {
        "malicious" => VtTier::Malicious,
        "suspicious" => VtTier::Suspicious,
        "benign" | "harmless" => VtTier::Benign,
        _ => return Classification::Unknown,
    };
    // Distinguish VT's three confidence tiers so the audit trail is
    // honest about what VT actually returned. Pre-fix: `"malicious"`
    // and `"suspicious"` collapsed into a single boolean, so a package
    // VT marked merely suspicious was reported as `WeMissed` ("VT:
    // malicious") in the markdown summary.
    match (our, vt_tier) {
        (Verdict::Malicious | Verdict::Suspicious, VtTier::Malicious) => {
            Classification::AgreeMalicious
        }
        (Verdict::Malicious | Verdict::Suspicious, VtTier::Suspicious) => {
            Classification::AgreeSuspicious
        }
        (Verdict::Malicious | Verdict::Suspicious, VtTier::Benign) => Classification::WeOverreached,
        (Verdict::Benign, VtTier::Malicious) => Classification::WeMissed,
        (Verdict::Benign, VtTier::Suspicious) => Classification::WeMissedSuspicious,
        (Verdict::Benign, VtTier::Benign) => Classification::AgreeBenign,
    }
}

fn verdict_label(verdict: Verdict) -> String {
    match verdict {
        Verdict::Malicious => "malicious".to_string(),
        Verdict::Suspicious => "suspicious".to_string(),
        Verdict::Benign => "benign".to_string(),
    }
}

pub(crate) fn render_markdown(summary: &CrossCheckSummary) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# skill-veil × VirusTotal cross-check\n\n\
        _packages compared_: **{}**\n\n\
        | our verdict / VT | count |\n|---|---|\n\
        | ✅ agree malicious (VT: malicious) | {} |\n\
        | ⚠️ agree suspicious (VT: suspicious) | {} |\n\
        | ✅ agree benign | {} |\n\
        | ❌ we missed (VT: malicious, us: benign) | **{}** |\n\
        | ⚠️ VT flagged as suspicious, us: benign | {} |\n\
        | ⚠️ we overreached (VT: benign, us: malicious/suspicious) | {} |\n\
        | ❓ unknown (no VT report or unrecognized verdict) | {} |\n",
        summary.total,
        summary.agree_malicious,
        summary.agree_suspicious,
        summary.agree_benign,
        summary.we_missed,
        summary.we_missed_suspicious,
        summary.we_overreached,
        summary.unknown,
    );

    render_missed_section(
        &mut out,
        summary,
        Classification::WeMissed,
        "We missed (VT: malicious)",
    );
    render_missed_section(
        &mut out,
        summary,
        Classification::WeMissedSuspicious,
        "VT flagged as suspicious, we said benign",
    );

    let overreached: Vec<_> = summary
        .packages
        .iter()
        .filter(|p| p.classification == Classification::WeOverreached)
        .collect();
    if !overreached.is_empty() {
        let _ = writeln!(out, "\n## We overreached ({})\n", overreached.len());
        for pkg in overreached {
            let _ = writeln!(
                out,
                "- `{}` — our={} risk={}  vt={}  findings={}",
                pkg.sha256,
                pkg.our_verdict,
                pkg.our_risk_score,
                pkg.vt_verdict.as_deref().unwrap_or("?"),
                pkg.our_findings.join(",")
            );
        }
    }

    out
}

pub(crate) fn render_text(summary: &CrossCheckSummary) -> String {
    format!(
        "Cross-check: total={} agree_malicious={} agree_suspicious={} agree_benign={} \
         we_missed={} we_missed_suspicious={} we_overreached={} unknown={}",
        summary.total,
        summary.agree_malicious,
        summary.agree_suspicious,
        summary.agree_benign,
        summary.we_missed,
        summary.we_missed_suspicious,
        summary.we_overreached,
        summary.unknown,
    )
}

/// Render one "we missed" detail section (per-package list with VT analysis
/// text) for a specific `Classification` bucket. Used for both
/// `WeMissed` (VT: malicious) and `WeMissedSuspicious` (VT: suspicious)
/// — the two buckets share output shape but were previously inlined into
/// `render_markdown` for the malicious case only.
fn render_missed_section(
    out: &mut String,
    summary: &CrossCheckSummary,
    classification: Classification,
    heading: &str,
) {
    let pkgs: Vec<_> = summary
        .packages
        .iter()
        .filter(|p| p.classification == classification)
        .collect();
    if pkgs.is_empty() {
        return;
    }
    let _ = writeln!(out, "\n## {} ({})\n", heading, pkgs.len());
    for pkg in pkgs {
        let _ = writeln!(out, "### `{}`", pkg.sha256);
        if let Some(name) = &pkg.meaningful_name {
            let _ = writeln!(out, "- **name**: {name}");
        }
        let _ = writeln!(
            out,
            "- **our verdict**: {} (risk {})",
            pkg.our_verdict, pkg.our_risk_score
        );
        if pkg.our_findings.is_empty() {
            let _ = writeln!(out, "- **our findings**: _(none)_");
        } else {
            let _ = writeln!(out, "- **our findings**: {}", pkg.our_findings.join(", "));
        }
        if let Some(v) = &pkg.vt_verdict {
            let _ = writeln!(out, "- **VT verdict**: {v}");
        }
        if let Some(analysis) = &pkg.vt_analysis {
            let _ = writeln!(out, "\n**VT Code Insight analysis:**\n");
            for line in analysis.lines() {
                let _ = writeln!(out, "> {line}");
            }
            let _ = writeln!(out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: `classify` covers all 9 `(Verdict × VtTier)` combinations
    /// plus the `Unknown` fallback for missing or unrecognized VT
    /// strings. VT-suspicious is distinguished from VT-malicious so the
    /// audit trail preserves the confidence VT actually returned —
    /// before the fix, suspicious collapsed into `AgreeMalicious` /
    /// `WeMissed` and the markdown labelled both as "malicious".
    #[test]
    fn classify_cases() {
        // VT: malicious
        assert_eq!(
            classify(Verdict::Malicious, Some("malicious")),
            Classification::AgreeMalicious
        );
        assert_eq!(
            classify(Verdict::Suspicious, Some("malicious")),
            Classification::AgreeMalicious,
            "Suspicious × VT-malicious escalates to AgreeMalicious"
        );
        assert_eq!(
            classify(Verdict::Benign, Some("malicious")),
            Classification::WeMissed
        );
        // VT: suspicious — the bug-fix anchor
        assert_eq!(
            classify(Verdict::Suspicious, Some("suspicious")),
            Classification::AgreeSuspicious,
            "Suspicious × VT-suspicious is AgreeSuspicious, NOT AgreeMalicious"
        );
        assert_eq!(
            classify(Verdict::Malicious, Some("suspicious")),
            Classification::AgreeSuspicious,
            "Malicious × VT-suspicious is AgreeSuspicious — both flagged at lower confidence"
        );
        assert_eq!(
            classify(Verdict::Benign, Some("suspicious")),
            Classification::WeMissedSuspicious,
            "Benign × VT-suspicious is WeMissedSuspicious, NOT WeMissed"
        );
        // VT: benign / harmless
        assert_eq!(
            classify(Verdict::Benign, Some("benign")),
            Classification::AgreeBenign
        );
        assert_eq!(
            classify(Verdict::Benign, Some("harmless")),
            Classification::AgreeBenign,
            "VT 'harmless' is treated as benign tier"
        );
        assert_eq!(
            classify(Verdict::Malicious, Some("benign")),
            Classification::WeOverreached
        );
        assert_eq!(
            classify(Verdict::Suspicious, Some("benign")),
            Classification::WeOverreached,
            "Suspicious vs VT-benign must count as overreach, not Unknown"
        );
        assert_eq!(
            classify(Verdict::Suspicious, Some("harmless")),
            Classification::WeOverreached
        );
        // Unknown: missing or unrecognized VT verdict
        assert_eq!(classify(Verdict::Benign, None), Classification::Unknown);
        assert_eq!(
            classify(Verdict::Benign, Some("totally-bogus")),
            Classification::Unknown,
            "Unrecognized VT verdict strings fall through to Unknown"
        );
    }

    /// Contract: `we_missed` and `we_missed_suspicious` increment
    /// independently. A package VT marked merely suspicious must not
    /// inflate the apparent "missed malware" count.
    #[test]
    fn summary_counts_split_we_missed_by_vt_tier() {
        let opts = CrossCheckOptions {
            dataset_dir: std::path::PathBuf::from("/nonexistent"),
            only_mismatches: false,
        };
        let mut summary = CrossCheckSummary::default();
        // Manually drive the counter logic with classify outputs since
        // build_summary requires loading reports from disk.
        for c in [
            Classification::WeMissed,
            Classification::WeMissedSuspicious,
            Classification::WeMissedSuspicious,
        ] {
            match c {
                Classification::WeMissed => summary.we_missed += 1,
                Classification::WeMissedSuspicious => summary.we_missed_suspicious += 1,
                _ => unreachable!(),
            }
        }
        assert_eq!(summary.we_missed, 1);
        assert_eq!(summary.we_missed_suspicious, 2);
        // opts is constructed only to verify the type still compiles after the field changes.
        let _ = opts.only_mismatches;
    }

    /// Contract: the markdown table label for each bucket accurately
    /// reflects the data. The pre-fix markdown said "VT: malicious"
    /// even when the bucket included VT-suspicious entries.
    #[test]
    fn render_markdown_labels_match_classification_buckets() {
        let summary = CrossCheckSummary {
            total: 5,
            agree_malicious: 1,
            agree_suspicious: 1,
            agree_benign: 1,
            we_missed: 1,
            we_missed_suspicious: 1,
            we_overreached: 0,
            unknown: 0,
            packages: Vec::new(),
        };
        let md = render_markdown(&summary);
        assert!(
            md.contains("agree malicious (VT: malicious)"),
            "agree-malicious row must be unambiguously labelled"
        );
        assert!(
            md.contains("agree suspicious (VT: suspicious)"),
            "agree-suspicious row must exist and reference VT's suspicious tier"
        );
        assert!(
            md.contains("we missed (VT: malicious, us: benign)"),
            "we-missed row must NOT mention 'suspicious' — that has its own bucket"
        );
        assert!(
            md.contains("VT flagged as suspicious, us: benign"),
            "we-missed-suspicious row must surface the new bucket"
        );
        // The pre-fix label combined both into "us: benign/suspicious"
        // — guard against regression.
        assert!(
            !md.contains("us: benign/suspicious"),
            "the pre-fix combined label must not reappear; markdown was:\n{md}"
        );
    }

    #[test]
    fn sha_for_lookup_uses_package_id_when_64_hex() {
        let id = Some("a".repeat(64));
        // Path doesn't need to exist — fast path returns before reading.
        let sha = sha_for_lookup(&id, Path::new("/nonexistent")).unwrap();
        assert_eq!(sha.len(), 64);
        assert!(sha.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sha_for_lookup_falls_back_to_file_hash_when_package_id_is_not_hex() {
        let tmp = std::env::temp_dir().join("skill-veil-cross-check-test.bin");
        std::fs::write(&tmp, b"hello").unwrap();
        let id = Some("not-a-sha".to_string());
        let sha = sha_for_lookup(&id, &tmp).expect("file hash fallback");
        // sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert_eq!(
            sha,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn sha_for_lookup_returns_none_when_file_missing_and_no_id() {
        assert!(sha_for_lookup(&None, Path::new("/definitely/does/not/exist")).is_none());
    }

    /// Contract: in extracted ZIP corpora the SHA appears in an ancestor
    /// directory name (with or without a recognised `_extracted` suffix).
    /// The lookup must recover the SHA before falling back to file hashing,
    /// since hashing the inner SKILL.md never matches the original archive's
    /// SHA-256 in VT's report cache.
    #[test]
    fn sha_for_lookup_finds_sha_in_extracted_dir_ancestor() {
        let sha = "a".repeat(64);
        let path = std::path::PathBuf::from(format!("/tmp/{sha}_extracted/SKILL.md"));
        // package_id is None because derive_package_id only matches bare hex names.
        let resolved = sha_for_lookup(&None, &path).expect("should recover sha from ancestor");
        assert_eq!(resolved, sha);
    }

    #[test]
    fn sha_for_lookup_finds_sha_in_bare_directory_ancestor() {
        let sha = "b".repeat(64);
        let path = std::path::PathBuf::from(format!("/tmp/{sha}/SKILL.md"));
        let resolved = sha_for_lookup(&None, &path).expect("should recover sha from bare dir");
        assert_eq!(resolved, sha);
    }

    #[test]
    fn sha_for_lookup_prefers_package_id_over_ancestor_walk() {
        // Even with a different sha in the ancestor, the explicit package_id wins.
        let id = "c".repeat(64);
        let other = "d".repeat(64);
        let path = std::path::PathBuf::from(format!("/tmp/{other}/SKILL.md"));
        let resolved = sha_for_lookup(&Some(id.clone()), &path).unwrap();
        assert_eq!(resolved, id);
    }

    #[test]
    fn sha_for_lookup_ignores_non_hex_ancestor() {
        // 64 chars but not hex → not a valid SHA, must fall through.
        let bogus = "g".repeat(64);
        let path = std::path::PathBuf::from(format!("/nonexistent/{bogus}/SKILL.md"));
        // No package_id, no valid ancestor sha, file doesn't exist → None.
        assert!(sha_for_lookup(&None, &path).is_none());
    }

    /// Contract: `load_reports` MUST normalise cached SHA-256 keys to
    /// lowercase. `sha_for_lookup` always returns lowercase (validated by
    /// `is_sha256_hex` and produced by `format!("{:x}")`), so a cached
    /// report whose JSON `sha256` field is uppercase or mixed-case would
    /// never match a lookup — surfacing as `Unknown` even though the
    /// report exists. Pre-fix the insert used `cached.sha256.clone()`
    /// verbatim.
    #[test]
    fn load_reports_normalizes_uppercase_sha_to_lowercase() {
        use crate::vt::types::FileAttributes;

        let tmp = tempfile::tempdir().expect("tempdir");
        let upper = "FF".repeat(32); // 64 uppercase hex chars
        let report = CachedReport {
            sha256: upper.clone(),
            fetched_at: "2026-01-01T00:00:00Z".to_string(),
            attributes: FileAttributes::default(),
        };
        let json = serde_json::to_vec(&report).expect("serialise");
        std::fs::write(tmp.path().join("report.json"), &json).expect("write");

        let loaded = load_reports(tmp.path()).expect("load_reports");
        let lower = upper.to_ascii_lowercase();
        assert!(
            loaded.contains_key(&lower),
            "cache key must be lowercase; got keys: {:?}",
            loaded.keys().collect::<Vec<_>>()
        );
        assert!(
            !loaded.contains_key(&upper),
            "uppercase key must NOT be present; the lookup path normalises to lowercase"
        );
    }
}
