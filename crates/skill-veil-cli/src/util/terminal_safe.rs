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
/// We strip every ASCII control byte (`0x00..=0x1F`, `0x7F`), the C1
/// control set (`0x80..=0x9F`) reachable through UTF-8, and Unicode
/// bidi format controls that reorder visible text without being
/// classified as `char::is_control()`. Tabs are replaced with a single
/// space (preserving column alignment), and other controls (newlines,
/// BEL, NUL, ESC, bidi overrides) are replaced with `?` because they
/// would visually break or spoof the indented output block; line and
/// column metadata already lives in dedicated fields rendered
/// separately.
pub(crate) fn sanitise_for_terminal(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c == '\t' {
                ' '
            } else if c.is_control() || is_bidi_format_control(c) || is_invisible_format(c) {
                '?'
            } else {
                c
            }
        })
        .collect()
}

fn is_bidi_format_control(c: char) -> bool {
    matches!(
        c,
        '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
    )
}

/// Zero-width / invisible format characters that render as nothing yet can
/// splice or hide visible text — e.g. make `evil.com` read as one token, or
/// smuggle ASCII through the tag block (U+E0000-U+E007F). They are not
/// `char::is_control()`, so they would otherwise reach the TTY unfiltered and
/// let a crafted indicator hide attacker-controlled bytes from the operator.
fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{200b}'..='\u{200d}'      // zero-width space / non-joiner / joiner
            | '\u{2060}'..='\u{2064}' // word joiner + invisible math operators
            | '\u{feff}'             // zero-width no-break space (BOM)
            | '\u{180e}'             // Mongolian vowel separator
            | '\u{115f}' | '\u{1160}' | '\u{3164}' | '\u{ffa0}' // Hangul fillers
            | '\u{e0000}'..='\u{e007f}' // tag block (ASCII smuggling)
    )
}

/// Maximum number of bytes of an HTTP error response body that an API
/// client embeds into a `*Error::HttpStatus` value. A hostile or
/// misbehaving gateway can return multi-kilobyte HTML/script payloads;
/// capping at construction keeps every downstream consumer
/// (`tracing::warn!`, `eprintln!`, structured-output formatters) bounded.
pub(crate) const ERROR_BODY_MAX_BYTES: usize = 512;

/// Truncate `body` to at most [`ERROR_BODY_MAX_BYTES`] bytes, ending on a
/// UTF-8 char boundary, appending `"...[truncated]"` when shortened.
///
/// The body is first run through [`sanitise_for_terminal`] so the capped
/// string is safe to print to an operator TTY. Shared by the VT, LLM, and
/// PromptIntel API clients so the error-body bound has one implementation.
pub(crate) fn truncate_error_body(body: String) -> String {
    let body = sanitise_for_terminal(&body);
    if body.len() <= ERROR_BODY_MAX_BYTES {
        debug_assert!(
            !body.chars().any(|c| c.is_control()),
            "error bodies must be terminal-safe"
        );
        return body;
    }
    let mut end = ERROR_BODY_MAX_BYTES;
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(end + 14);
    out.push_str(&body[..end]);
    out.push_str("...[truncated]");
    debug_assert!(
        !out.chars().any(|c| c.is_control()),
        "error bodies must be terminal-safe"
    );
    out
}

/// Build the error-body string embedded in a `*Error::HttpStatus` value
/// from the result of reading a size-capped response body.
///
/// On success the body is run through [`truncate_error_body`]; on a read
/// failure the error is logged — so a gateway 502 / mid-stream disconnect
/// stays diagnosable instead of surfacing as an empty body with no clue —
/// and an empty string is returned, keeping the public error shape
/// unchanged. Shared by the VT, LLM, and PromptIntel clients: `source`
/// names the client in the log line, and the generic error type accepts
/// each client's distinct reader error (`std::io::Error` vs
/// `anyhow::Error`).
pub(crate) fn drain_error_body<E: std::fmt::Display>(
    source: &str,
    status: u16,
    read: Result<String, E>,
) -> String {
    match read {
        Ok(body) => truncate_error_body(body),
        Err(err) => {
            tracing::warn!(
                "{source} returned HTTP {status} but the response body could not be read: {err}"
            );
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        drain_error_body, sanitise_for_terminal, truncate_error_body, ERROR_BODY_MAX_BYTES,
    };

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

    /// Contract: Unicode bidi format controls MUST be neutralised. They
    /// are not `char::is_control()`, but terminals and renderers still
    /// use them to reorder visible text. A filename like
    /// `safe\u{202e}gpj.exe` can be displayed as an innocuous-looking
    /// extension while preserving attacker-controlled bytes in the
    /// underlying path.
    #[test]
    fn sanitise_for_terminal_replaces_bidi_format_controls() {
        let attacker = "safe\u{202e}gpj.exe";
        let cleaned = sanitise_for_terminal(attacker);

        assert!(!cleaned.contains('\u{202e}'));
        assert_eq!(cleaned, "safe?gpj.exe");
    }

    /// Contract: zero-width / invisible format characters MUST be neutralised.
    /// They render as nothing, so `evil\u{200b}.com` would display as
    /// `evil.com` in the diff/finding output and a tag-block run
    /// (U+E0000-U+E007F) smuggles invisible ASCII — both let a crafted
    /// indicator hide bytes from the operator.
    #[test]
    fn sanitise_for_terminal_replaces_invisible_format_characters() {
        assert_eq!(sanitise_for_terminal("evil\u{200b}.com"), "evil?.com");
        assert_eq!(sanitise_for_terminal("a\u{feff}b"), "a?b");
        assert_eq!(sanitise_for_terminal("x\u{2060}y"), "x?y");
        let tag_block = "hi\u{e0041}\u{e0042}";
        let cleaned = sanitise_for_terminal(tag_block);
        assert!(!cleaned.contains('\u{e0041}') && !cleaned.contains('\u{e0042}'));
        assert_eq!(cleaned, "hi??");
        // Printable Unicode (accents, CJK) is untouched.
        assert_eq!(sanitise_for_terminal("café 日本"), "café 日本");
    }

    /// Contract: a body shorter than [`ERROR_BODY_MAX_BYTES`] is preserved
    /// verbatim so the cap doesn't silently shorten ordinary API error
    /// messages — operator diagnostics need the gateway's actual hint when
    /// it's already small.
    #[test]
    fn truncate_keeps_short_payloads_intact() {
        let body = "quota exceeded for this hour".to_string();
        assert_eq!(truncate_error_body(body.clone()), body);
    }

    /// Contract: error bodies are terminal-safe before they become a
    /// `*Error::HttpStatus`; enrichment prints those errors to stderr when
    /// the remote side fails.
    #[test]
    fn truncate_sanitises_control_bytes() {
        let body = "gateway \x1b[2J\x1b[Hfake ok".to_string();

        let cleaned = truncate_error_body(body);

        assert!(!cleaned.contains('\x1b'));
        assert!(cleaned.contains("gateway "));
    }

    /// Contract: a body longer than [`ERROR_BODY_MAX_BYTES`] is truncated
    /// with a visible suffix. An attacker-controlled MITM (or a gateway
    /// outage page) could otherwise push multi-KB HTML into operator logs
    /// and terminals. The cap is enforced at the producer so every
    /// downstream consumer inherits the bound.
    #[test]
    fn truncate_caps_long_payloads_with_suffix() {
        let huge = "Y".repeat(ERROR_BODY_MAX_BYTES * 4);
        let truncated = truncate_error_body(huge);
        assert!(
            truncated.len() <= ERROR_BODY_MAX_BYTES + "...[truncated]".len(),
            "truncated body must be capped, got len={}",
            truncated.len()
        );
        assert!(
            truncated.ends_with("...[truncated]"),
            "truncated body must carry the suffix; got tail: {:?}",
            &truncated[truncated.len().saturating_sub(20)..]
        );
    }

    /// Contract: a successful read drains to the truncated body — the
    /// success branch must NOT drop the gateway's diagnostic text (the
    /// VT/LLM/PromptIntel clients rely on the body reaching
    /// `*Error::HttpStatus`).
    #[test]
    fn drain_error_body_returns_truncated_body_on_ok() {
        let read: Result<String, std::io::Error> = Ok("upstream-down".to_string());
        assert_eq!(drain_error_body("test", 503, read), "upstream-down");
    }

    /// Contract: a read failure drains to an empty string (the public error
    /// shape is unchanged) rather than propagating the read error.
    #[test]
    fn drain_error_body_returns_empty_on_read_error() {
        let read: Result<String, std::io::Error> =
            Err(std::io::Error::other("mid-stream disconnect"));
        assert_eq!(drain_error_body("test", 502, read), "");
    }

    /// Contract: truncation never splits a multi-byte UTF-8 character. The
    /// `is_char_boundary` walk-back guards against `String` slicing panicking
    /// when `ERROR_BODY_MAX_BYTES` lands inside a codepoint; an off-by-one
    /// would corrupt the diagnostic string and crash a downstream JSON parser
    /// that re-reads it.
    #[test]
    fn truncate_respects_utf8_char_boundary() {
        // 4-byte UTF-8 char (U+1F600 grinning face) repeated until the body
        // exceeds the cap, so the byte cap never falls cleanly on a char
        // boundary at offsets like 511.
        let body = "\u{1F600}".repeat(200);
        assert!(body.len() > ERROR_BODY_MAX_BYTES);
        let truncated = truncate_error_body(body);
        let _ = std::str::from_utf8(truncated.as_bytes())
            .expect("truncated body must remain valid UTF-8");
        assert!(truncated.ends_with("...[truncated]"));
        assert!(truncated.len() < ERROR_BODY_MAX_BYTES + 32);
    }
}
