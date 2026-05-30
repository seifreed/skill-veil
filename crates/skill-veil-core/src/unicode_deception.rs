//! Detects Unicode-based deception in any text artifact: invisible/zero-width
//! characters, bidirectional-override controls (Trojan Source), Unicode tag
//! blocks (ASCII smuggling), and single-token mixed-script homoglyphs.
//!
//! These attacks hide instructions or disguise identifiers in ways a
//! regex over the visible text cannot see — a payload like `ex\u{200b}ec`
//! reads as the keyword to the model but not to a literal pattern. The
//! detector runs over the primary document and every supporting artifact and
//! emits one `Finding` per `(category, artifact)`.
//!
//! False-positive discipline is built into the classifiers rather than the
//! verdict layer: a leading byte-order mark is ignored, invisible characters
//! count only when embedded in ASCII alphanumeric text (so legitimate emoji
//! ZWJ sequences and Indic/Arabic joiners do not fire), and the mixed-script
//! check is restricted to Latin↔Cyrillic / Latin↔Greek inside one token
//! (the classic homoglyph attack) so ordinary multilingual prose such as
//! `iPhone手机` is left alone.

use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};

/// Characters of evidence context retained around the first occurrence.
const EVIDENCE_CONTEXT_CHARS: usize = 24;
/// Minimum token length considered for mixed-script homoglyph analysis.
/// Single characters carry no homoglyph signal and short tokens inflate
/// false positives on transliterated abbreviations.
const MIN_HOMOGLYPH_TOKEN_LEN: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeceptionKind {
    InvisibleChars,
    BidiOverride,
    TagBlock,
    HomoglyphMix,
}

impl DeceptionKind {
    fn rule_id(self) -> &'static str {
        match self {
            DeceptionKind::InvisibleChars => "UNICODE_INVISIBLE_CHARS",
            DeceptionKind::BidiOverride => "UNICODE_BIDI_OVERRIDE",
            DeceptionKind::TagBlock => "UNICODE_TAG_BLOCK",
            DeceptionKind::HomoglyphMix => "UNICODE_HOMOGLYPH_MIX",
        }
    }

    fn category(self) -> ThreatCategory {
        match self {
            // A tag-block run is the on-the-wire form of a hidden prompt:
            // invisible to a human reviewer, decoded as ASCII by the model.
            DeceptionKind::TagBlock => ThreatCategory::PersistentPromptTampering,
            _ => ThreatCategory::Obfuscation,
        }
    }

    fn severity(self) -> Severity {
        match self {
            DeceptionKind::TagBlock | DeceptionKind::BidiOverride => Severity::High,
            DeceptionKind::InvisibleChars | DeceptionKind::HomoglyphMix => Severity::Medium,
        }
    }

    fn reason(self) -> &'static str {
        match self {
            DeceptionKind::InvisibleChars => {
                "invisible/zero-width characters embedded in text can hide instructions or disguise identifiers"
            }
            DeceptionKind::BidiOverride => {
                "bidirectional-override control characters can reorder source so rendered text differs from logical content (Trojan Source)"
            }
            DeceptionKind::TagBlock => {
                "Unicode tag-block characters (U+E0000-U+E007F) encode hidden ASCII invisible to humans but read by the model (ASCII smuggling)"
            }
            DeceptionKind::HomoglyphMix => {
                "a single token mixes Latin with Cyrillic or Greek look-alike characters, a homoglyph disguise"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Script {
    Latin,
    Cyrillic,
    Greek,
    Other,
}

fn script_of(c: char) -> Script {
    match c {
        'a'..='z' | 'A'..='Z' => Script::Latin,
        '\u{00C0}'..='\u{024F}' => Script::Latin, // Latin-1 supplement + Latin Extended-A/B
        '\u{0370}'..='\u{03FF}' | '\u{1F00}'..='\u{1FFF}' => Script::Greek,
        '\u{0400}'..='\u{052F}' => Script::Cyrillic,
        _ => Script::Other,
    }
}

/// Zero-width and invisible-format characters used to smuggle content into
/// otherwise-ASCII text. The byte-order mark (U+FEFF) is handled separately
/// by the caller because a leading BOM is legitimate.
fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'        // zero-width space
            | '\u{200C}'  // zero-width non-joiner
            | '\u{200D}'  // zero-width joiner
            | '\u{2060}'  // word joiner
            | '\u{2061}'
            ..='\u{2064}' // invisible math operators
            | '\u{FEFF}'  // zero-width no-break space (non-leading)
            | '\u{180E}'  // Mongolian vowel separator
            | '\u{061C}'  // Arabic letter mark
            | '\u{115F}'  // Hangul choseong filler
            | '\u{1160}'  // Hangul jungseong filler
            | '\u{3164}'  // Hangul filler
            | '\u{FFA0}' // halfwidth Hangul filler
    )
}

fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{202A}'..='\u{202E}' // LRE RLE PDF LRO RLO
            | '\u{2066}'..='\u{2069}' // LRI RLI FSI PDI
    )
}

fn is_tag_block(c: char) -> bool {
    ('\u{E0000}'..='\u{E007F}').contains(&c)
}

#[derive(Debug, Clone)]
struct Occurrence {
    kind: DeceptionKind,
    line: usize,
    count: usize,
    sample: String,
}

/// Scan one artifact's text for every Unicode-deception category and return a
/// `Finding` per category that fired.
pub(crate) fn scan_unicode_deception(
    content: &str,
    artifact_kind: ArtifactKind,
    artifact_path: &str,
) -> Vec<Finding> {
    collect_occurrences(content)
        .into_iter()
        .map(|occ| build_finding(&occ, artifact_kind, artifact_path))
        .collect()
}

fn collect_occurrences(content: &str) -> Vec<Occurrence> {
    let chars: Vec<char> = content.chars().collect();
    let mut invisible: Option<Occurrence> = None;
    let mut bidi: Option<Occurrence> = None;
    let mut tag: Option<Occurrence> = None;

    let mut line = 1usize;
    for (idx, &c) in chars.iter().enumerate() {
        if c == '\n' {
            line += 1;
            continue;
        }
        // A byte-order mark at the very start of the file is legitimate.
        let leading_bom = idx == 0 && c == '\u{FEFF}';
        if !leading_bom && is_invisible_format(c) && embedded_in_ascii(&chars, idx) {
            record(&mut invisible, DeceptionKind::InvisibleChars, line, c);
        } else if is_bidi_control(c) {
            record(&mut bidi, DeceptionKind::BidiOverride, line, c);
        } else if is_tag_block(c) {
            record(&mut tag, DeceptionKind::TagBlock, line, c);
        }
    }

    let mut out: Vec<Occurrence> = [invisible, bidi, tag].into_iter().flatten().collect();
    if let Some(occ) = detect_homoglyph_mix(content) {
        out.push(occ);
    }
    out
}

fn record(slot: &mut Option<Occurrence>, kind: DeceptionKind, line: usize, c: char) {
    match slot {
        Some(occ) => occ.count += 1,
        None => {
            *slot = Some(Occurrence {
                kind,
                line,
                count: 1,
                sample: format!("U+{:04X}", c as u32),
            });
        }
    }
}

/// True when the character at `idx` neighbours ASCII alphanumeric text on
/// either side (skipping a run of adjacent invisible characters). This is the
/// signature of smuggling into Latin text/identifiers and excludes legitimate
/// joiners between emoji or non-Latin scripts.
fn embedded_in_ascii(chars: &[char], idx: usize) -> bool {
    let left = chars[..idx]
        .iter()
        .rev()
        .find(|c| !is_invisible_format(**c))
        .is_some_and(|c| c.is_ascii_alphanumeric());
    let right = chars[idx + 1..]
        .iter()
        .find(|c| !is_invisible_format(**c))
        .is_some_and(|c| c.is_ascii_alphanumeric());
    left || right
}

fn detect_homoglyph_mix(content: &str) -> Option<Occurrence> {
    for (line_idx, line) in content.lines().enumerate() {
        for token in line.split_whitespace() {
            if token.chars().count() < MIN_HOMOGLYPH_TOKEN_LEN {
                continue;
            }
            let (mut latin, mut cyrillic, mut greek) = (false, false, false);
            for c in token.chars() {
                match script_of(c) {
                    Script::Latin => latin = true,
                    Script::Cyrillic => cyrillic = true,
                    Script::Greek => greek = true,
                    Script::Other => {}
                }
            }
            if latin && (cyrillic || greek) {
                return Some(Occurrence {
                    kind: DeceptionKind::HomoglyphMix,
                    line: line_idx + 1,
                    count: 1,
                    sample: token.chars().take(EVIDENCE_CONTEXT_CHARS).collect(),
                });
            }
        }
    }
    None
}

fn build_finding(occ: &Occurrence, artifact_kind: ArtifactKind, artifact_path: &str) -> Finding {
    let action = match occ.kind.severity() {
        Severity::Critical | Severity::High => RecommendedAction::Block,
        Severity::Medium => RecommendedAction::RequireApproval,
        Severity::Low => RecommendedAction::Log,
    };
    Finding::builder(occ.kind.rule_id(), occ.kind.category())
        .severity(occ.kind.severity())
        .confidence(0.85)
        .matched_on(MatchTarget::ReferencedFile {
            path: artifact_path.to_string(),
        })
        .match_value(format!(
            "{} ×{} (first sample: {})",
            occ.sample, occ.count, occ.sample
        ))
        .reason(occ.kind.reason())
        .action(action)
        .evidence_kind(EvidenceKind::Behavior)
        .artifact(artifact_kind, Some(artifact_path.to_string()))
        .line(occ.line)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(content: &str) -> Vec<Finding> {
        scan_unicode_deception(content, ArtifactKind::SkillDocument, "/tmp/SKILL.md")
    }

    fn fired(content: &str, rule_id: &str) -> bool {
        scan(content).iter().any(|f| f.rule_id == rule_id)
    }

    #[test]
    fn zero_width_inside_ascii_word_fires() {
        // `ru<ZWSP>n` reads as one word to a model but not to a literal regex.
        assert!(fired("please ru\u{200b}n now", "UNICODE_INVISIBLE_CHARS"));
    }

    #[test]
    fn leading_bom_does_not_fire() {
        assert!(!fired(
            "\u{FEFF}# Normal skill document",
            "UNICODE_INVISIBLE_CHARS"
        ));
    }

    #[test]
    fn emoji_zwj_sequence_does_not_fire() {
        // Family emoji uses ZWJ between non-ASCII pictographs — legitimate.
        assert!(!fired(
            "team: \u{1F468}\u{200d}\u{1F469}\u{200d}\u{1F467}",
            "UNICODE_INVISIBLE_CHARS"
        ));
    }

    #[test]
    fn bidi_override_fires() {
        assert!(fired("name = \u{202E}txt.bin", "UNICODE_BIDI_OVERRIDE"));
    }

    #[test]
    fn plain_ascii_has_no_bidi() {
        assert!(!fired("name = file.bin", "UNICODE_BIDI_OVERRIDE"));
    }

    #[test]
    fn tag_block_fires() {
        // U+E0041 is tag-block 'A'.
        assert!(fired("hello \u{E0041}\u{E0042}", "UNICODE_TAG_BLOCK"));
    }

    #[test]
    fn homoglyph_latin_cyrillic_mix_fires() {
        // `pаypal` — the second char is Cyrillic 'а' (U+0430), not Latin 'a'.
        assert!(fired(
            "login at p\u{0430}ypal portal",
            "UNICODE_HOMOGLYPH_MIX"
        ));
    }

    #[test]
    fn pure_ascii_token_has_no_homoglyph() {
        assert!(!fired("login at paypal portal", "UNICODE_HOMOGLYPH_MIX"));
    }

    #[test]
    fn latin_cjk_mix_does_not_fire_homoglyph() {
        // Ordinary multilingual prose must not be flagged.
        assert!(!fired(
            "the iPhone\u{624B}\u{673A} model",
            "UNICODE_HOMOGLYPH_MIX"
        ));
    }

    #[test]
    fn clean_document_produces_no_findings() {
        assert!(scan("# Skill\n\nA perfectly normal description with code `sum()`.").is_empty());
    }

    #[test]
    fn finding_is_anchored_to_artifact_with_line() {
        let findings = scan_unicode_deception(
            "line one\nplease ru\u{200b}n",
            ArtifactKind::ReferencedArtifact,
            "/tmp/scripts/x.py",
        );
        let f = findings
            .iter()
            .find(|f| f.rule_id == "UNICODE_INVISIBLE_CHARS")
            .expect("expected invisible-char finding");
        assert_eq!(f.line_number, Some(2));
        assert_eq!(f.artifact_path.as_deref(), Some("/tmp/scripts/x.py"));
    }

    #[test]
    fn repeated_invisible_chars_count_in_one_finding() {
        let findings = scan("a\u{200b}b c\u{200b}d e\u{200b}f");
        let invis: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "UNICODE_INVISIBLE_CHARS")
            .collect();
        assert_eq!(invis.len(), 1, "one consolidated finding per artifact");
        assert!(invis[0].match_value.contains("×3"));
    }
}
