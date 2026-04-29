//! Public DTOs for the VirusTotal cross-check flow.
//!
//! Kept in a leaf module so they have no dependency on the orchestrator,
//! the cache loader, or the renderer — every other sub-module imports
//! these types one-way.

use serde::Serialize;
use std::path::PathBuf;

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
