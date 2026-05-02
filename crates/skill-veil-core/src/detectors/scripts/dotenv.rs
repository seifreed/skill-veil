//! Word-boundary helper for detecting genuine `.env` (dotenv) references.
//!
//! Naive `lower.contains(".env")` matches `.envrc`, `.envelope`, and any
//! identifier whose lowercased form contains the substring. Detectors that
//! flag dotenv reads as exfiltration sources (taint sinks, capability
//! discovery) MUST route through [`references_dotenv_file`] so a benign
//! `cat .envrc` does not produce a Critical/Block taint finding.

/// Return `true` when `lower` contains a reference to a genuine dotenv
/// asset. Matches:
///
/// - `dotenv` / `load_dotenv` (the explicit library names),
/// - `.env` immediately followed by a separator that ends the filename
///   (`"`, `'`, end-of-string, whitespace, `:`, `,`, `)`, `;`, `` ` ``),
/// - `/.env` or `\.env` (an absolute or POSIX-style path),
/// - `read .env` / `cat .env` (shell-form references).
///
/// Rejects `.envrc`, `.envelope`, `.environments/foo`, and identifier-style
/// substrings such as `MY.ENV` because the surrounding bytes are not a
/// recognised filename terminator/initiator.
///
/// # Contract
///
/// `lower` MUST already be ASCII-lowercased — this matches the invariant
/// shared with the detector pipeline (`original_match_str`) and avoids
/// allocating a second copy.
#[must_use]
pub(crate) fn references_dotenv_file(lower: &str) -> bool {
    if lower.contains("dotenv") || lower.contains("load_dotenv") {
        return true;
    }
    let mut search_start = 0;
    while let Some(rel) = lower[search_start..].find(".env") {
        let abs = search_start + rel;
        let after = abs + ".env".len();
        let next = lower[after..].chars().next();
        let is_terminator = match next {
            None => true,
            Some(c) => matches!(
                c,
                '"' | '\'' | ' ' | '\t' | '\n' | '\r' | ':' | ',' | ')' | ';' | '`' | '.'
            ),
        };
        if is_terminator {
            let before = lower[..abs].chars().next_back();
            let before_ok = matches!(
                before,
                None | Some(
                    '"' | '\'' | '/' | '\\' | ' ' | '\t' | '(' | ',' | ':' | '`' | '=' | '-'
                )
            );
            if before_ok {
                return true;
            }
        }
        search_start = abs + 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Contract
    ///
    /// Lookalike filenames whose lowercased form contains `.env` as a
    /// non-boundary substring MUST NOT be classified as dotenv references.
    /// Pre-fix the bare-substring check produced Critical taint findings
    /// on benign `cat .envrc` lines.
    #[test]
    fn rejects_lookalike_filenames() {
        for sample in [
            "source .envrc",
            "cat .envelope",
            "open(.environments/prod.conf)",
            "let v = MY.ENV;",
            "value = some.envoy.config",
            "read .envoy_config",
        ] {
            assert!(
                !references_dotenv_file(&sample.to_ascii_lowercase()),
                "must not match lookalike: {sample}"
            );
        }
    }

    /// # Contract
    ///
    /// Genuine dotenv references in the canonical shell, JS, and Python
    /// forms MUST match.
    #[test]
    fn fires_on_genuine_dotenv_references() {
        for sample in [
            "cat .env",
            "open(\".env\")",
            "fs.readFileSync('.env')",
            "VALUE=$(cat .env)",
            "from dotenv import load_dotenv",
            "require('dotenv').config()",
            "cat /etc/secrets/.env",
            "read .env",
        ] {
            assert!(
                references_dotenv_file(&sample.to_ascii_lowercase()),
                "must match genuine reference: {sample}"
            );
        }
    }

    /// # Contract
    ///
    /// Standard dotenv variant files (`.env.local`, `.env.production`,
    /// `.env.staging`, `.env.development`) are genuine secret-bearing
    /// files that MUST be detected. Pre-fix the terminator character set
    /// after `.env` excluded `.`, so `cat .env.local` was rejected —
    /// an attacker storing secrets in `.env.local` would bypass the
    /// Critical/Block taint finding.
    #[test]
    fn fires_on_dotenv_variant_files() {
        for sample in [
            "cat .env.local",
            "cat .env.production",
            "cat .env.staging",
            "cat .env.development",
            "cat .env.test",
            "fs.readFileSync('.env.local')",
            "open(\".env.production\")",
        ] {
            assert!(
                references_dotenv_file(&sample.to_ascii_lowercase()),
                "must match dotenv variant: {sample}"
            );
        }
        // `.environment` is NOT a dotenv variant — must still be rejected.
        assert!(
            !references_dotenv_file("cat .environment"),
            "must not match .environment"
        );
    }
}
