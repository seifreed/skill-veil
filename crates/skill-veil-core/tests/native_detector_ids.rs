use std::collections::BTreeSet;
use std::path::Path;

use serde::Deserialize;
use skill_veil_core::{ScanOptions, Scanner, NATIVE_DETECTOR_RULE_IDS};
use tempfile::TempDir;

#[derive(Deserialize)]
struct Corpus {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    rule_id: String,
    artifact: String,
    expect_match: bool,
    content: String,
    /// For the `pyc` artifact only: write a sibling `payload.py` source so
    /// the `BYTECODE_PYC_SOURCELESS` negative case can be expressed.
    #[serde(default)]
    with_source: bool,
}

fn expand(raw: &str) -> String {
    raw.replace("\\n", "\n")
        .replace("{ZWSP}", "\u{200B}")
        .replace("{RLO}", "\u{202E}")
        .replace("{TAGA}", "\u{E0041}")
        .replace("{TAGB}", "\u{E0042}")
        .replace("{CYR_A}", "\u{0430}")
}

/// Decode a hex string (whitespace ignored) to bytes. Used by `pyc`
/// fixtures to embed raw `.pyc` headers and marshalled bodies inline.
fn hex_decode(raw: &str) -> Vec<u8> {
    let digits: Vec<u8> = raw
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            other => panic!("invalid hex digit: {other}"),
        })
        .collect();
    assert!(
        digits.len().is_multiple_of(2),
        "hex fixture must have even length"
    );
    digits.chunks_exact(2).map(|p| (p[0] << 4) | p[1]).collect()
}

fn fixture_scanner() -> Scanner {
    Scanner::with_std_adapters(ScanOptions {
        honor_inline_suppressions: false,
        ..Default::default()
    })
    .unwrap()
}

fn entrypoint_name(artifact: &str) -> &'static str {
    match artifact {
        "skill" => "SKILL.md",
        "mcp" => "mcp.json",
        "manifest" => "package.json",
        other => panic!("unknown artifact kind in fixture: {other}"),
    }
}

#[test]
fn native_detector_ids_match_fixture_corpus() {
    let manifest =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/native_detector_ids.yaml");
    let corpus: Corpus =
        serde_yaml::from_str(&std::fs::read_to_string(&manifest).unwrap()).unwrap();
    let scanner = fixture_scanner();

    let mut failures = Vec::new();
    let mut positives_seen = BTreeSet::new();

    for case in &corpus.cases {
        let dir = TempDir::new().unwrap();
        let scan_target = if case.artifact == "pyc" {
            // The bytecode detector fires on a `.pyc` discovered alongside a
            // skill entrypoint, not on a single text file. Lay out a minimal
            // package: SKILL.md (the explicit entrypoint) + payload.pyc (the
            // hex-encoded bytecode) + an optional payload.py source.
            let skill = dir.path().join("SKILL.md");
            std::fs::write(&skill, "# Fixture Skill\n\nReferences payload.pyc\n").unwrap();
            std::fs::write(dir.path().join("payload.pyc"), hex_decode(&case.content)).unwrap();
            if case.with_source {
                std::fs::write(dir.path().join("payload.py"), "print(1)\n").unwrap();
            }
            skill
        } else {
            let path = dir.path().join(entrypoint_name(&case.artifact));
            std::fs::write(&path, expand(&case.content)).unwrap();
            path
        };

        let result = scanner.scan_file(&scan_target).unwrap();
        let fired = result.findings.iter().any(|f| f.rule_id == case.rule_id);
        if fired != case.expect_match {
            failures.push(format!(
                "[{}] {} expected match={} but observed {}",
                case.id, case.rule_id, case.expect_match, fired
            ));
        }
        if case.expect_match {
            positives_seen.insert(case.rule_id.clone());
        }
    }

    assert!(
        failures.is_empty(),
        "native detector ID fixtures regressed:\n{}",
        failures.join("\n")
    );

    let registry: BTreeSet<String> = NATIVE_DETECTOR_RULE_IDS
        .iter()
        .map(|id| (*id).to_string())
        .collect();
    let uncovered: Vec<&String> = registry.difference(&positives_seen).collect();
    assert!(
        uncovered.is_empty(),
        "every registered native ID needs a positive fixture; missing: {uncovered:?}"
    );
}
