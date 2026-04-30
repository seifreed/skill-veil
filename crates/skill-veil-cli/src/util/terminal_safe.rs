//! Terminal-safe rendering of attacker-controlled strings.
//!
//! Several CLI surfaces emit attacker-controlled bytes directly to the
//! operator's TTY: scanned skill content (`finding.match_value`,
//! `finding.artifact_path`) goes through the text formatter, and the
//! VT enrichment subsystem writes IOC indicators (URLs, domains, IPs
//! extracted from a malicious skill) to stdout. A crafted indicator
//! like `https://evil.invalid/\x1b[2J\x1b[H` would clear the terminal
//! and could be used to repaint a fake verdict.
//!
//! This module is the single boundary where attacker bytes must be
//! filtered before reaching the TTY. Color escapes applied by
//! [`crate::color::ColorMode`] wrap a fixed, audited palette around
//! already-sanitised content, so they cannot be the entry point for
//! attacker-controlled escape sequences.

/// Replace any byte the user terminal might interpret as a control
/// instruction with `?`, leaving printable text intact. The text-output
/// formatter and the VT enrichment formatter render untrusted document
/// content directly into the terminal stream, so a crafted skill could
/// embed CSI / OSC sequences that clear the screen, repaint the
/// verdict, or open an OSC-8 hyperlink to an attacker URL.
///
/// We strip every ASCII control byte (`0x00..=0x1F`, `0x7F`) plus the
/// C1 control set (`0x80..=0x9F`) reachable through UTF-8. Tabs are
/// replaced with a single space (preserving column alignment), and
/// other controls (newlines, BEL, NUL, ESC) are replaced with `?`
/// because they would visually break the indented output block; line
/// and column metadata already lives in dedicated fields rendered
/// separately.
pub(crate) fn sanitise_for_terminal(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c == '\t' {
                ' '
            } else if c.is_control() {
                '?'
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::sanitise_for_terminal;

    /// Contract: bare ASCII control characters (`\x1b`, `\x07`, `\x00`,
    /// etc.) MUST be replaced with `?` so a crafted skill cannot clear
    /// the operator's terminal, repaint a fake verdict, or open an
    /// OSC-8 hyperlink. CSI sequences embedded in match values would
    /// otherwise let an attacker rewrite the visible output to claim a
    /// passing scan, or surface a `\x1b]8;;<url>\x07Click here\x1b]8;;\x07`
    /// hyperlink that opens an attacker URL when the operator clicks
    /// the finding.
    #[test]
    fn sanitise_for_terminal_replaces_control_bytes_with_question_mark() {
        let attacker = "BENIGN \x1b[2J\x1b[H FAKE OK \x07\x00";
        let cleaned = sanitise_for_terminal(attacker);
        assert!(
            !cleaned.contains('\x1b'),
            "ESC must be stripped from terminal output"
        );
        assert!(!cleaned.contains('\x07'), "BEL must be stripped");
        assert!(!cleaned.contains('\x00'), "NUL must be stripped");
        assert!(cleaned.starts_with("BENIGN "), "printable prefix preserved");
    }

    /// Contract: tabs and newlines MUST be replaced because they
    /// visually break the indented finding/IOC block. Tabs collapse to
    /// a single space (keeping column alignment); newlines/CR are
    /// stripped to `?` so an attacker cannot inject blank lines that
    /// fragment the output and hide critical findings beneath
    /// attacker-controlled padding.
    #[test]
    fn sanitise_for_terminal_replaces_layout_breakers() {
        let value = "left\tmiddle\nend\rtail";
        let cleaned = sanitise_for_terminal(value);
        assert!(!cleaned.contains('\t'));
        assert!(!cleaned.contains('\n'));
        assert!(!cleaned.contains('\r'));
        assert!(cleaned.contains("left middle"));
    }

    /// Contract: printable Unicode (accented letters, CJK, emoji)
    /// MUST be preserved verbatim. `is_control()` only flags the C0
    /// and C1 control sets, so these characters round-trip unchanged.
    /// Pinning the contract so a future tightening of the filter
    /// doesn't accidentally strip non-Latin content from match values
    /// or URL paths.
    #[test]
    fn sanitise_for_terminal_preserves_printable_unicode() {
        let value = "curl https://example.invalid/installer-üñîcödé.sh";
        let cleaned = sanitise_for_terminal(value);
        assert_eq!(cleaned, value);
    }

    /// Contract: an OSC-8 hyperlink ending with `\x07` (or
    /// `\x1b\\\\`) MUST be neutralised in both the opening and
    /// closing terminator. A URL like
    /// `\x1b]8;;https://evil.invalid\x07Click\x1b]8;;\x07` would
    /// otherwise turn the rendered indicator into a clickable link to
    /// the attacker's destination.
    #[test]
    fn sanitise_for_terminal_neutralises_osc8_hyperlinks() {
        let attacker = "\x1b]8;;https://evil.invalid\x07click\x1b]8;;\x07";
        let cleaned = sanitise_for_terminal(attacker);
        assert!(!cleaned.contains('\x1b'));
        assert!(!cleaned.contains('\x07'));
    }
}
