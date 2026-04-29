//! Orchestration entry point for manifest detectors. The actual rule
//! logic lives in `crate::detectors::manifests`; this module re-exports
//! the public detector functions and hosts a couple of small helpers
//! (`sibling_has_file`, `strip_inline_*_comment`) that orchestration
//! shares with detectors.

mod container;

pub(crate) use crate::detectors::manifests::build::{
    analyze_makefile, makefile_capabilities, makefile_relations,
};
pub(crate) use crate::detectors::manifests::javascript::{
    analyze_npmrc, analyze_package_json, npmrc_capabilities, npmrc_relations,
    package_json_capabilities, package_json_expected_lockfiles, package_json_relations,
};
pub(crate) use crate::detectors::manifests::python::{
    analyze_pip_conf, analyze_pyproject_toml, analyze_requirements_txt, pip_conf_capabilities,
    pip_conf_relations, pyproject_expected_lockfiles, pyproject_toml_capabilities,
    requirements_txt_capabilities,
};
pub(crate) use crate::detectors::manifests::rust_cargo::{
    analyze_cargo_toml, cargo_toml_capabilities,
};
pub(crate) use container::{
    analyze_docker_compose, analyze_dockerfile, docker_compose_capabilities,
    docker_compose_relations, dockerfile_capabilities, dockerfile_relations,
};

use std::path::PathBuf;

pub(crate) fn sibling_has_file(sibling_files: &[PathBuf], name: &str) -> bool {
    sibling_files.iter().any(|f| {
        f.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case(name))
    })
}

/// Drop everything from the first `#` in a Makefile / Dockerfile line so
/// inline comments don't bleed into substring detectors.
///
/// Scanning `line.starts_with('#')` only suppresses lines whose **first**
/// non-whitespace character is `#`; an inline comment such as
/// `RUN echo ok # was: curl example.com` still leaves `curl ` in the
/// lowercased line and would otherwise trigger
/// `MANIFEST_MAKEFILE_REMOTE_DOWNLOAD` or the Dockerfile NetworkAccess
/// capability. We split on the first `#` because both Makefile and
/// Dockerfile use `#` as the line comment marker — neither supports `#`
/// inside an unquoted command token, so this is safe for the substring
/// detectors that consume the result.
///
/// Use [`strip_inline_ini_comment`] for INI-style configs (`.npmrc`,
/// `pip.conf`) that also accept `;` as a comment marker. Do NOT use the
/// INI variant on `requirements.txt` (where `;` is the PEP 508
/// environment-marker separator, e.g. `requests; python_version>='3.6'`).
pub(crate) fn strip_inline_hash_comment(line: &str) -> &str {
    line.split_once('#').map(|(code, _)| code).unwrap_or(line)
}

/// Drop everything from the first INI comment marker (`#` or `;`),
/// whichever appears earliest.
///
/// `.npmrc` and `pip.conf` follow INI syntax and accept both markers
/// interchangeably, so a line like `; _authtoken=PLACEHOLDER` (full-line
/// comment) and `_authtoken=secret ; rotate me` (inline comment) must
/// both have the comment stripped before substring detectors see the
/// content. Returns the prefix preserving original casing/whitespace.
///
/// Not appropriate for `requirements.txt` — there `;` introduces a PEP
/// 508 environment marker, not a comment. Use [`strip_inline_hash_comment`]
/// for that case.
pub(crate) fn strip_inline_ini_comment(line: &str) -> &str {
    let hash_idx = line.find('#');
    let semi_idx = line.find(';');
    match (hash_idx, semi_idx) {
        (Some(h), Some(s)) => &line[..h.min(s)],
        (Some(h), None) => &line[..h],
        (None, Some(s)) => &line[..s],
        (None, None) => line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: lines without a `#` are returned verbatim.
    #[test]
    fn strip_inline_hash_comment_preserves_lines_without_hash() {
        assert_eq!(
            strip_inline_hash_comment("curl https://x"),
            "curl https://x"
        );
        assert_eq!(strip_inline_hash_comment(""), "");
    }

    /// Contract: the comment portion (and the `#` itself) is dropped, but
    /// the code preceding it is preserved unchanged.
    #[test]
    fn strip_inline_hash_comment_drops_inline_trailing_comment() {
        assert_eq!(
            strip_inline_hash_comment("\t@echo done  # was: curl https://old"),
            "\t@echo done  ",
        );
        assert_eq!(
            strip_inline_hash_comment("RUN echo ok # curl example.com"),
            "RUN echo ok ",
        );
    }

    /// Contract: a line that starts with `#` collapses to empty so the
    /// downstream substring detectors see nothing.
    #[test]
    fn strip_inline_hash_comment_collapses_pure_comment_to_empty() {
        assert_eq!(strip_inline_hash_comment("# curl evil.example"), "");
        assert_eq!(strip_inline_hash_comment("#bash install.sh"), "");
    }

    /// Contract: with neither `#` nor `;`, the line is returned verbatim.
    #[test]
    fn strip_inline_ini_comment_preserves_lines_without_marker() {
        assert_eq!(
            strip_inline_ini_comment("registry=https://registry.npmjs.org"),
            "registry=https://registry.npmjs.org"
        );
    }

    /// Contract: `;` introduces a comment in INI files. Lines starting
    /// with `;` collapse to the empty prefix.
    #[test]
    fn strip_inline_ini_comment_treats_semicolon_as_comment_marker() {
        assert_eq!(strip_inline_ini_comment("; _authtoken=PLACEHOLDER"), "");
        assert_eq!(
            strip_inline_ini_comment("_authtoken=secret ; rotate me"),
            "_authtoken=secret "
        );
    }

    /// Contract: `#` and `;` are interchangeable; whichever appears
    /// first wins so a `#` inside the trailing portion of a `;`-comment
    /// (or vice versa) doesn't survive into the returned prefix.
    #[test]
    fn strip_inline_ini_comment_uses_earliest_marker() {
        // `;` precedes `#` → cut at `;`, the `#` is inside the comment.
        assert_eq!(
            strip_inline_ini_comment("foo=bar ; note # rotate"),
            "foo=bar "
        );
        // `#` precedes `;` → cut at `#`.
        assert_eq!(
            strip_inline_ini_comment("foo=bar # note ; rotate"),
            "foo=bar "
        );
    }
}
