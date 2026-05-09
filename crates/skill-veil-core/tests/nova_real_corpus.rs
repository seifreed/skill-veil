//! Integration test: every `.nov` rule in the canonical NOVA pack
//! parses cleanly. The pack ships at
//! <https://github.com/Nova-Hunting/nova-rules>; this test reads from
//! `$NOVA_RULES_DIR` (set by CI / dev to a checkout or extracted
//! tarball) and skips silently when the env var is absent so the
//! standard `cargo test` run does not require network.
//!
//! Pre-fix the parser had a bug where keyword variable names were
//! stored with the `$` prefix while condition references stripped it,
//! causing every published NOVA rule to fail with a spurious
//! `DanglingReference`. This test pins the round-trip against the
//! real upstream corpus so the same regression cannot land again.

use skill_veil_core::nova::parser::parse_rules;
use std::ffi::OsStr;
use std::path::Path;

fn for_each_nov_file_in(dir: &Path, f: &mut dyn FnMut(&Path, &str)) {
    if !dir.is_dir() {
        return;
    }
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            for_each_nov_file_in(&path, f);
        } else if path.extension() == Some(OsStr::new("nov")) {
            let body = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            f(&path, &body);
        }
    }
}

#[test]
fn every_real_nova_rule_parses_when_corpus_path_is_provided() {
    let Ok(dir) = std::env::var("NOVA_RULES_DIR") else {
        eprintln!(
            "skipping nova_real_corpus: set NOVA_RULES_DIR to a checkout / \
             extracted tarball of github.com/Nova-Hunting/nova-rules"
        );
        return;
    };
    let dir = Path::new(&dir);
    let mut total = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for_each_nov_file_in(dir, &mut |path, body| {
        total += 1;
        if let Err(err) = parse_rules(body) {
            failures.push(format!("{}: {err}", path.display()));
        }
    });
    assert!(total > 0, "no .nov files found under {}", dir.display());
    assert!(
        failures.is_empty(),
        "{}/{} NOVA rules failed to parse:\n  - {}",
        failures.len(),
        total,
        failures.join("\n  - ")
    );
}
