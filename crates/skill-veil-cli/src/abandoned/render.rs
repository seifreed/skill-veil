//! Render the abandoned-package advisory block. All registry-supplied strings
//! pass through the terminal sanitiser, matching the OSV/VT formatters.

use super::types::{AbandonedPackage, AbandonedReason};
use crate::util::terminal_safe::sanitise_for_terminal;
use std::fmt::Write as _;

/// Characters of a deprecation message retained in the block.
const DETAIL_MAX_CHARS: usize = 140;

pub(super) fn render(flagged: &[AbandonedPackage], queried: usize, skipped: usize) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "\n=== Abandoned / Unmaintained Packages (informational; does not affect skill-veil verdict) ==="
    );
    let _ = writeln!(
        out,
        "  checked {queried} package{} ({skipped} skipped: unsupported/unsafe name); {} flagged",
        if queried == 1 { "" } else { "s" },
        flagged.len(),
    );
    for pkg in flagged {
        let label = match pkg.reason {
            AbandonedReason::Deprecated => "deprecated",
            AbandonedReason::Stale => "unmaintained",
        };
        let truncated: String = pkg.detail.chars().take(DETAIL_MAX_CHARS).collect();
        let _ = writeln!(
            out,
            "    - {} ({}): {} — {}",
            sanitise_for_terminal(&pkg.name),
            pkg.ecosystem.osv_name(),
            label,
            sanitise_for_terminal(&truncated),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use skill_veil_core::Ecosystem;

    #[test]
    fn render_lists_flagged_packages() {
        let flagged = vec![
            AbandonedPackage {
                name: "request".to_string(),
                ecosystem: Ecosystem::Npm,
                reason: AbandonedReason::Deprecated,
                detail: "request has been deprecated".to_string(),
            },
            AbandonedPackage {
                name: "oldlib".to_string(),
                ecosystem: Ecosystem::PyPI,
                reason: AbandonedReason::Stale,
                detail: "last published 2016-01-01".to_string(),
            },
        ];
        let out = render(&flagged, 5, 1);
        assert!(out.contains("request (npm): deprecated"));
        assert!(out.contains("oldlib (PyPI): unmaintained"));
        assert!(out.contains("2 flagged"));
        assert!(out.contains("does not affect skill-veil verdict"));
    }

    #[test]
    fn render_sanitises_control_bytes() {
        let flagged = vec![AbandonedPackage {
            name: "p\x1b[2J".to_string(),
            ecosystem: Ecosystem::Npm,
            reason: AbandonedReason::Deprecated,
            detail: "boom\x07".to_string(),
        }];
        let out = render(&flagged, 1, 0);
        assert!(!out.contains('\x1b'));
        assert!(!out.contains('\x07'));
    }
}
