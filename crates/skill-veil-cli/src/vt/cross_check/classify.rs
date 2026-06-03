//! Decision logic mapping `(our verdict, VT verdict)` to a `Classification`.
//!
//! Pure function over enums — no I/O, no string parsing beyond
//! lowercase normalisation of VT's verdict tag. Lives in its own module
//! so the truth table stays small and reviewable.

use super::types::Classification;
use skill_veil_core::Verdict;

#[derive(Debug, Clone, Copy)]
enum VtTier {
    Malicious,
    Suspicious,
    Benign,
}

pub(super) fn classify(our: Verdict, vt_category: Option<&str>) -> Classification {
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
}
