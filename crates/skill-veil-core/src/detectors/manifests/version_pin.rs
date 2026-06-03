//! Shared lexical checks for exact version pins across manifest detectors.
//!
//! The npm SemVer and Poetry PEP 440-ish exact-pin checks validate the same
//! `MAJOR.MINOR.PATCH[-pre][+build]` shape; they differ only in the equality
//! prefix each strips before calling [`is_exact_dotted_version_pin`].

/// Split `value` on the first `delimiter`, returning the remainder as `Some`
/// only when the delimiter was present.
fn split_once_optional(value: &str, delimiter: char) -> (&str, Option<&str>) {
    value
        .split_once(delimiter)
        .map_or((value, None), |(left, right)| (left, Some(right)))
}

/// True when `version` is an exact `MAJOR.MINOR.PATCH` pin with optional
/// `-<identifiers>` pre-release and `+<identifiers>` build metadata, where the
/// core parts are non-empty numeric runs and each identifier segment is a
/// non-empty run of ASCII alphanumerics and hyphens.
pub(crate) fn is_exact_dotted_version_pin(version: &str) -> bool {
    let (without_build, build) = split_once_optional(version, '+');
    if build.is_some_and(|value| !is_dotted_alnum_hyphen_list(value)) {
        return false;
    }
    let (core, prerelease) = split_once_optional(without_build, '-');
    if prerelease.is_some_and(|value| !is_dotted_alnum_hyphen_list(value)) {
        return false;
    }
    let mut parts = core.split('.');
    let (Some(major), Some(minor), Some(patch)) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    parts.next().is_none()
        && [major, minor, patch]
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn is_dotted_alnum_hyphen_list(value: &str) -> bool {
    !value.is_empty()
        && value.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: a bare `MAJOR.MINOR.PATCH` triple of numeric parts is an
    /// exact pin, with optional pre-release and build identifier lists.
    #[test]
    fn accepts_exact_triples_with_optional_metadata() {
        assert!(is_exact_dotted_version_pin("1.2.3"));
        assert!(is_exact_dotted_version_pin("1.2.3-alpha.1"));
        assert!(is_exact_dotted_version_pin("1.2.3+build.1"));
        assert!(is_exact_dotted_version_pin("1.2.3-rc-1+build-2"));
    }

    /// Contract: anything that is not a strict three-part numeric core, or
    /// whose identifier lists contain disallowed characters, is not an exact
    /// pin (so the caller treats it as floating/unpinned).
    #[test]
    fn rejects_ranges_partials_and_bad_identifiers() {
        assert!(!is_exact_dotted_version_pin("1.2"));
        assert!(!is_exact_dotted_version_pin("1.2.3.4"));
        assert!(!is_exact_dotted_version_pin("1.x.3"));
        assert!(!is_exact_dotted_version_pin("1.2.3-"));
        assert!(!is_exact_dotted_version_pin("1.2.3-bad_id"));
        assert!(!is_exact_dotted_version_pin(""));
    }

    /// Contract: the optional-split helper only reports a remainder when the
    /// delimiter is actually present.
    #[test]
    fn split_once_optional_reports_presence() {
        assert_eq!(split_once_optional("a-b", '-'), ("a", Some("b")));
        assert_eq!(split_once_optional("ab", '-'), ("ab", None));
    }
}
