//! Python ecosystem manifest detectors. Each format owns its own
//! submodule; this `mod.rs` hosts only the shared dependency-name
//! parser (`parse_python_dep_name`) and the canonical name lists,
//! both consumed by `requirements.rs` and `pyproject.rs`.

mod pip_conf;
mod pyproject;
mod requirements;

pub(crate) use pip_conf::{analyze_pip_conf, pip_conf_capabilities, pip_conf_relations};
pub(crate) use pyproject::{
    analyze_pyproject_toml, pyproject_expected_lockfiles, pyproject_toml_capabilities,
};
pub(crate) use requirements::{analyze_requirements_txt, requirements_txt_capabilities};

pub(super) const PYTHON_NETWORK_DEPS: &[&str] = &[
    "requests",
    "httpx",
    "aiohttp",
    "urllib3",
    "paramiko",
    "grpcio",
    "websockets",
    "tornado",
];

pub(super) const PYTHON_EXEC_DEPS: &[&str] = &["subprocess32", "pexpect", "fabric", "invoke"];

pub(super) const PYTHON_VCS_PREFIXES: &[&str] = &["git+", "hg+", "svn+", "bzr+"];

pub(super) fn starts_with_ignore_ascii_case(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

pub(super) fn has_python_vcs_prefix(line: &str) -> bool {
    PYTHON_VCS_PREFIXES
        .iter()
        .any(|prefix| starts_with_ignore_ascii_case(line, prefix))
}

/// Extract the canonical lowercase package name from a single dependency
/// spec line (already stripped of inline comments and trimmed).
///
/// # Contract
///
/// Recognised shapes:
/// - Plain: `requests`, `requests==2.0.0`, `requests>=2.0`, `requests~=2.0`,
///   `requests[security]>=2.0`, `requests; python_version>='3.6'`.
/// - PEP 508 direct reference: `NAME @ URL`, with optional whitespace around
///   `@` and optional extras on `NAME`.
/// - Legacy VCS with egg fragment: `git+https://host/repo.git#egg=NAME`,
///   plus `hg+`, `svn+`, `bzr+`. The name comes from the `egg=` fragment.
///
/// Returns `None` for VCS specs without a recoverable name (no `egg=`,
/// no PEP 508 prefix) — the caller cannot map those to a known dep.
pub(super) fn parse_python_dep_name(line: &str) -> Option<String> {
    if let Some(dep_name) = parse_direct_reference_name(line) {
        return Some(dep_name);
    }
    if has_python_vcs_prefix(line) {
        for fragment in line.split('#').skip(1) {
            for kv in fragment.split('&') {
                if let Some(value) = kv.trim().strip_prefix("egg=") {
                    if let Some(name) = canonical_python_requirement_name(value) {
                        return Some(name);
                    }
                }
            }
        }
        return None;
    }
    let name = line
        .split(['=', '>', '<', '~', '!', '[', ';', ' '])
        .next()
        .unwrap_or("")
        .trim();
    canonical_python_requirement_name(name)
}

fn parse_direct_reference_name(line: &str) -> Option<String> {
    let (name, target) = line.split_once('@')?;
    if target.trim().is_empty() {
        return None;
    }
    canonical_python_requirement_name(name)
}

fn canonical_python_requirement_name(name: &str) -> Option<String> {
    let base = name.split('[').next().unwrap_or("").trim();
    if is_python_distribution_name(base) {
        return Some(canonical_python_name(base));
    }
    None
}

fn is_python_distribution_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && name
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn canonical_python_name(name: &str) -> String {
    name.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: PEP 508 direct references allow compact `name@url` syntax.
    #[test]
    fn parse_python_dep_name_accepts_compact_direct_reference() {
        let dep = parse_python_dep_name("requests@git+https://github.com/psf/requests.git");
        assert_eq!(dep.as_deref(), Some("requests"));
    }

    /// Contract: extras belong to the requirement selector, not to the
    /// canonical dependency name used by capability inference.
    #[test]
    fn parse_python_dep_name_removes_direct_reference_extras() {
        let dep = parse_python_dep_name("requests[security] @ https://example.invalid/pkg.whl");
        assert_eq!(dep.as_deref(), Some("requests"));
    }

    /// Contract: URL userinfo in a raw VCS URL is not a PEP 508 direct
    /// reference name. Without `egg=`, the dependency name is unknown.
    #[test]
    fn parse_python_dep_name_rejects_vcs_userinfo_without_egg() {
        let dep = parse_python_dep_name("git+ssh://git@github.com/example/tool.git");
        assert_eq!(dep, None);
    }

    /// Contract: VCS URL schemes are URL schemes and are matched
    /// case-insensitively before preserving `#egg=` fragments.
    #[test]
    fn parse_python_dep_name_accepts_case_variant_vcs_prefix() {
        let dep = parse_python_dep_name("GIT+https://github.com/psf/requests.git#egg=requests");
        assert_eq!(dep.as_deref(), Some("requests"));
    }
}
