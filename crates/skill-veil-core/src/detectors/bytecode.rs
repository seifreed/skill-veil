//! Native Python `.pyc` bytecode-integrity detector.
//!
//! Cisco's skill-scanner ships a dedicated bytecode engine because
//! compiled `.pyc` objects are a real malware carrier: an attacker can
//! drop bytecode that never appears in any `.py` source a reviewer reads.
//! This detector inspects `.pyc` bytes directly and emits the
//! `BYTECODE_PYC_*` native IDs (see
//! [`crate::detectors::native_ids`]).
//!
//! Three signals, all from a single cheap pass over the bytes:
//! - invalid CPython header (`BYTECODE_PYC_INVALID_MAGIC`),
//! - bytecode shipped without its `.py` source (`BYTECODE_PYC_SOURCELESS`),
//! - process/network/eval primitives in the marshalled body
//!   (`BYTECODE_PYC_SUSPICIOUS_CONTENT`).

use std::path::Path;

use crate::detectors::native_ids::{
    BYTECODE_PYC_INVALID_MAGIC, BYTECODE_PYC_SOURCELESS, BYTECODE_PYC_SUSPICIOUS_CONTENT,
};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, SignalClass,
    ThreatCategory,
};

/// CPython `.pyc` files begin with a 16-byte header: a 4-byte magic, a
/// 4-byte bit-field, and 8 bytes of timestamp/size or source hash. The
/// magic's last two bytes are ALWAYS CR LF (`0x0d 0x0a`) across every
/// CPython release — present to detect FTP ASCII-mode corruption. A file
/// claiming to be `.pyc` without it is malformed or hand-crafted.
const PYC_HEADER_LEN: usize = 16;
const PYC_MAGIC_CR: u8 = 0x0d;
const PYC_MAGIC_LF: u8 = 0x0a;

/// High-signal byte markers whose presence in a marshalled body indicates
/// process, network, or dynamic-code primitives. Marshalled `str`/`bytes`
/// objects (string literals) store their content verbatim, and bare names
/// (module names, function names) are stored as individual `co_names` — both
/// reachable by a substring scan.
///
/// NOTE: a *dotted* attribute access (module-dot-method) is NOT stored as the
/// joined bytes — CPython marshals the module and the attribute as separate
/// `co_names`. So the dotted markers below only fire when the literal appears in
/// a string constant; the bare method-name and string-literal markers are what
/// catch real compiled payloads (base64/hex decode chains, reverse-shell
/// idioms). Bare names stay specific to avoid substring false positives
/// (`b64decode`, not `decode`; `mkfifo`, not `open`).
const SUSPICIOUS_MARKERS: &[&[u8]] = &[
    b"os.system",
    b"subprocess",
    b"__import__",
    b"/bin/sh",
    b"/bin/bash",
    b"marshal.loads",
    b"base64.b64decode",
    b"socket.socket",
    b"powershell",
    b"pty.spawn",
    // Bare forms that survive marshalling, plus reverse-shell string literals.
    b"b64decode",
    b"b85decode",
    b"b32decode",
    b"fromhex",
    b"/dev/tcp",
    b"mkfifo",
];

/// The fixed shape of one bytecode finding family. Grouping the six
/// per-finding constants keeps the emit helper to a small argument list.
struct BytecodeSignal {
    rule_id: &'static str,
    severity: Severity,
    category: ThreatCategory,
    signal: SignalClass,
    action: RecommendedAction,
    confidence: f32,
}

const INVALID_MAGIC_SIGNAL: BytecodeSignal = BytecodeSignal {
    rule_id: BYTECODE_PYC_INVALID_MAGIC,
    severity: Severity::High,
    category: ThreatCategory::SupplyChain,
    signal: SignalClass::SuspiciousPackageBehavior,
    action: RecommendedAction::RequireApproval,
    confidence: 0.7,
};

const SOURCELESS_SIGNAL: BytecodeSignal = BytecodeSignal {
    rule_id: BYTECODE_PYC_SOURCELESS,
    severity: Severity::Medium,
    category: ThreatCategory::SupplyChain,
    signal: SignalClass::ReviewSignal,
    action: RecommendedAction::Log,
    confidence: 0.55,
};

const SUSPICIOUS_SIGNAL: BytecodeSignal = BytecodeSignal {
    rule_id: BYTECODE_PYC_SUSPICIOUS_CONTENT,
    severity: Severity::Medium,
    category: ThreatCategory::RemoteExec,
    signal: SignalClass::SuspiciousPackageBehavior,
    action: RecommendedAction::RequireApproval,
    confidence: 0.5,
};

/// `true` when `path` has a Python bytecode extension (`.pyc` / `.pyo`).
#[must_use]
pub fn is_python_bytecode(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("pyc") || e.eq_ignore_ascii_case("pyo"))
}

#[must_use]
fn has_valid_pyc_header(bytes: &[u8]) -> bool {
    bytes.len() >= PYC_HEADER_LEN && bytes[2] == PYC_MAGIC_CR && bytes[3] == PYC_MAGIC_LF
}

#[must_use]
fn suspicious_markers_in_body(bytes: &[u8]) -> Vec<&'static str> {
    if bytes.len() <= PYC_HEADER_LEN {
        return Vec::new();
    }
    let body = &bytes[PYC_HEADER_LEN..];
    SUSPICIOUS_MARKERS
        .iter()
        .filter(|marker| body.windows(marker.len()).any(|w| w == **marker))
        .filter_map(|marker| std::str::from_utf8(marker).ok())
        .collect()
}

fn bytecode_finding(
    sig: &BytecodeSignal,
    path: &str,
    reason: impl Into<String>,
    match_value: Option<String>,
) -> Finding {
    let mut builder = Finding::builder(sig.rule_id, sig.category)
        .severity(sig.severity)
        .confidence(sig.confidence)
        .action(sig.action)
        .signal_class(sig.signal)
        .evidence_kind(EvidenceKind::Behavior)
        .artifact(ArtifactKind::ReferencedArtifact, Some(path.to_string()))
        .matched_on(MatchTarget::ReferencedFile {
            path: path.to_string(),
        })
        .reason(reason);
    if let Some(value) = match_value {
        builder = builder.match_value(value);
    }
    builder.build()
}

/// Analyse one `.pyc` artifact's raw bytes. `has_sibling_source` is `true`
/// when a `.py` file with the same stem sits next to the `.pyc`. Pure: the
/// caller does the I/O and the sibling lookup. An invalid header short-
/// circuits the body scans, whose byte offsets would otherwise be
/// unreliable.
#[must_use]
pub fn analyze_pyc(bytes: &[u8], has_sibling_source: bool, path: &Path) -> Vec<Finding> {
    let path_str = path.display().to_string();
    let mut findings = Vec::new();

    if !has_valid_pyc_header(bytes) {
        findings.push(bytecode_finding(
            &INVALID_MAGIC_SIGNAL,
            &path_str,
            "Python .pyc file lacks a valid CPython bytecode header \
             (CR/LF magic marker missing); malformed or hand-crafted bytecode",
            None,
        ));
        return findings;
    }

    if !has_sibling_source {
        findings.push(bytecode_finding(
            &SOURCELESS_SIGNAL,
            &path_str,
            "Compiled Python bytecode shipped without its .py source; \
             a common way to hide logic from source review",
            None,
        ));
    }

    let hits = suspicious_markers_in_body(bytes);
    if !hits.is_empty() {
        findings.push(bytecode_finding(
            &SUSPICIOUS_SIGNAL,
            &path_str,
            "Compiled Python bytecode references process/network/dynamic-code \
             primitives in its marshalled body",
            Some(hits.join(", ")),
        ));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// A 16-byte CPython header with the CR/LF magic marker, then `body`.
    fn pyc_with_body(body: &[u8]) -> Vec<u8> {
        let mut v = vec![0x6f, 0x0d, PYC_MAGIC_CR, PYC_MAGIC_LF];
        v.extend_from_slice(&[0u8; 12]);
        v.extend_from_slice(body);
        v
    }

    fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    #[test]
    fn invalid_header_fires_and_short_circuits() {
        let bytes = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let f = analyze_pyc(&bytes, true, Path::new("x.pyc"));
        assert_eq!(ids(&f), vec![BYTECODE_PYC_INVALID_MAGIC]);
    }

    #[test]
    fn too_short_is_invalid_header() {
        let f = analyze_pyc(
            &[0x6f, 0x0d, PYC_MAGIC_CR, PYC_MAGIC_LF],
            true,
            Path::new("x.pyc"),
        );
        assert_eq!(ids(&f), vec![BYTECODE_PYC_INVALID_MAGIC]);
    }

    #[test]
    fn valid_header_without_source_is_sourceless() {
        let bytes = pyc_with_body(b"print");
        let f = analyze_pyc(&bytes, false, Path::new("x.pyc"));
        assert_eq!(ids(&f), vec![BYTECODE_PYC_SOURCELESS]);
    }

    #[test]
    fn valid_header_with_source_and_benign_body_is_clean() {
        let bytes = pyc_with_body(b"print");
        let f = analyze_pyc(&bytes, true, Path::new("x.pyc"));
        assert!(f.is_empty(), "expected no findings, got {:?}", ids(&f));
    }

    #[test]
    fn suspicious_body_marker_fires_even_with_source() {
        let mut body = b"hello".to_vec();
        body.extend_from_slice(b"os.system");
        let bytes = pyc_with_body(&body);
        let f = analyze_pyc(&bytes, true, Path::new("x.pyc"));
        assert_eq!(ids(&f), vec![BYTECODE_PYC_SUSPICIOUS_CONTENT]);
    }

    #[test]
    fn sourceless_and_suspicious_stack() {
        let bytes = pyc_with_body(b"subprocess");
        let f = analyze_pyc(&bytes, false, Path::new("x.pyc"));
        assert_eq!(
            ids(&f),
            vec![BYTECODE_PYC_SOURCELESS, BYTECODE_PYC_SUSPICIOUS_CONTENT]
        );
    }

    #[test]
    fn marker_in_header_region_is_not_scanned() {
        // The marker overlaps only the 16-byte header, not the body.
        let mut bytes = vec![0x6f, 0x0d, PYC_MAGIC_CR, PYC_MAGIC_LF];
        bytes.extend_from_slice(b"os.system!!!");
        let f = analyze_pyc(&bytes, true, Path::new("x.pyc"));
        assert!(
            f.is_empty(),
            "header-region marker must not fire: {:?}",
            ids(&f)
        );
    }

    /// Contract: bare decode-method names and reverse-shell string literals
    /// appear verbatim in compiled bytecode (unlike dotted attribute accesses),
    /// so they fire the suspicious-content signal.
    #[test]
    fn realistic_bare_markers_fire_in_marshalled_body() {
        for marker in [
            b"b64decode".as_slice(),
            b"/dev/tcp".as_slice(),
            b"mkfifo".as_slice(),
        ] {
            let mut body = b"hello".to_vec();
            body.extend_from_slice(marker);
            let bytes = pyc_with_body(&body);
            let f = analyze_pyc(&bytes, true, Path::new("x.pyc"));
            assert!(
                ids(&f).contains(&BYTECODE_PYC_SUSPICIOUS_CONTENT),
                "marker {:?} must fire suspicious-content; got {:?}",
                std::str::from_utf8(marker).unwrap(),
                ids(&f)
            );
        }
    }

    #[test]
    fn is_python_bytecode_matches_extensions() {
        assert!(is_python_bytecode(Path::new("a/b.pyc")));
        assert!(is_python_bytecode(Path::new("a/b.PYO")));
        assert!(!is_python_bytecode(Path::new("a/b.py")));
        assert!(!is_python_bytecode(Path::new("a/b")));
    }
}
