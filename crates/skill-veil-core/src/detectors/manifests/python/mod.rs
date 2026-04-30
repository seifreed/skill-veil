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

/// Extract the canonical lowercase package name from a single dependency
/// spec line (already stripped of inline comments and trimmed).
///
/// # Contract
///
/// Recognised shapes:
/// - Plain: `requests`, `requests==2.0.0`, `requests>=2.0`, `requests~=2.0`,
///   `requests[security]>=2.0`, `requests; python_version>='3.6'`.
/// - PEP 508 direct reference: `NAME @ URL` (any URL form, including
///   `git+https://...`). The name precedes the ` @ ` separator.
/// - Legacy VCS with egg fragment: `git+https://host/repo.git#egg=NAME`,
///   plus `hg+`, `svn+`, `bzr+`. The name comes from the `egg=` fragment.
///
/// Returns `None` for VCS specs without a recoverable name (no `egg=`,
/// no PEP 508 prefix) — the caller cannot map those to a known dep.
pub(super) fn parse_python_dep_name(line: &str) -> Option<String> {
    if let Some((name, _)) = line.split_once(" @ ") {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            return Some(canonical_python_name(trimmed));
        }
    }
    if PYTHON_VCS_PREFIXES.iter().any(|p| line.starts_with(p)) {
        for fragment in line.split('#').skip(1) {
            for kv in fragment.split('&') {
                if let Some(value) = kv.trim().strip_prefix("egg=") {
                    let name = value.split(['[', ';']).next().unwrap_or("").trim();
                    if !name.is_empty() {
                        return Some(canonical_python_name(name));
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
    if name.is_empty() {
        return None;
    }
    Some(canonical_python_name(name))
}

fn canonical_python_name(name: &str) -> String {
    name.to_ascii_lowercase()
}
