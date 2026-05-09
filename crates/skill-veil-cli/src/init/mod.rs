//! `skill-veil init` — download, verify, and install the latest
//! `skill-veil-rules` release into the user cache.
//!
//! Pipeline (see individual submodule docs for the contract each
//! stage upholds):
//!
//! 1. Resolve the requested version (default: `latest` via the GitHub
//!    Releases redirect; explicit pin via `--version vX.Y.Z`).
//! 2. Download `manifest.json`, `manifest.json.sig`, and
//!    `skill-veil-rules-<version>.tar.gz` into a temp staging dir.
//! 3. Verify the Ed25519 signature of `manifest.json` against the
//!    embedded trusted keys. Reject if no key accepts.
//! 4. Extract the tarball into a separate temp dir with hardened path
//!    traversal + size protections.
//! 5. Verify per-file SHA-256 against the manifest, AND verify the
//!    extracted tree contains exactly what the manifest declares.
//! 6. Atomically rename the verified tree into
//!    `<cache_root>/skill-veil/rules/<version>/`, replacing any prior
//!    install of the same version.
//! 7. Update the `current` pointer (a small JSON file) so
//!    `default_external_rule_dirs()` knows which version to load.

mod download;
mod extract;
mod keys;
mod manifest;
mod verify;

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};

pub(crate) use download::ReleaseAssets;

/// Filename of the small JSON pointer that marks which installed
/// version is "current". Read by `default_external_rule_dirs()` and
/// `skill-veil rules status`.
pub(crate) const CURRENT_POINTER_FILENAME: &str = "current.json";

/// Outcome of a successful `init` run, returned to the CLI for human
/// rendering.
#[derive(Debug)]
pub(crate) struct InitOutcome {
    pub(crate) version: String,
    pub(crate) trusted_key_id: &'static str,
    pub(crate) install_dir: PathBuf,
    pub(crate) file_count: usize,
}

/// Top-level entry point.
///
/// `requested_version`:
///   - `Some("v0.1.0")` pins to that exact release.
///   - `None` resolves the latest stable release via GitHub.
///
/// `cache_root`:
///   - `Some(path)` overrides the install location (used by
///     `--cache-dir` and tests).
///   - `None` uses `dirs::cache_dir().join("skill-veil")`.
pub(crate) fn run_init(
    requested_version: Option<String>,
    cache_root: Option<PathBuf>,
) -> Result<InitOutcome> {
    let version = match requested_version {
        Some(v) => v,
        None => resolve_latest_version()?,
    };
    validate_version_string(&version)?;

    let cache_root = resolve_cache_root(cache_root)?;
    let install_root = cache_root.join("rules");
    std::fs::create_dir_all(&install_root)
        .with_context(|| format!("creating install root {}", install_root.display()))?;

    let staging = tempfile::tempdir_in(&install_root)
        .with_context(|| format!("creating staging dir under {}", install_root.display()))?;

    let assets = ReleaseAssets::for_version(&version);
    let downloaded = download::fetch_release(&assets, staging.path())
        .with_context(|| format!("downloading release {}", version))?;

    let trusted_key_id =
        verify::verify_manifest_signature(&downloaded.manifest_bytes, &downloaded.signature_bytes)
            .with_context(|| format!("verifying manifest signature for {}", version))?;

    let manifest: manifest::Manifest = serde_json::from_slice(&downloaded.manifest_bytes)
        .context("parsing manifest.json after signature verification")?;
    manifest.check_schema_version().map_err(|e| anyhow!(e))?;
    if manifest.version != version {
        anyhow::bail!(
            "manifest.json declares version `{}` but URL pinned `{}` — refusing to install \
             a release that does not match its own metadata",
            manifest.version,
            version
        );
    }

    let extract_root = staging.path().join("extract");
    extract::extract_into(&downloaded.tarball_path, &extract_root)
        .with_context(|| "extracting verified tarball")?;

    verify::verify_manifest_against_extracted(&manifest, &extract_root)
        .with_context(|| "verifying extracted files against the signed manifest")?;

    let install_dir = install_root.join(&version);
    if install_dir.exists() {
        // Replace atomically by removing first; ignore errors here
        // because the rename will surface a clearer error if the dir
        // is still occupied.
        std::fs::remove_dir_all(&install_dir).ok();
    }
    std::fs::rename(&extract_root, &install_dir).with_context(|| {
        format!(
            "atomic rename {} -> {}",
            extract_root.display(),
            install_dir.display()
        )
    })?;

    write_current_pointer(&install_root, &version, trusted_key_id)?;

    let file_count = manifest.files.len();
    Ok(InitOutcome {
        version,
        trusted_key_id,
        install_dir,
        file_count,
    })
}

/// Render outcome details for `skill-veil rules status`.
pub(crate) fn current_install(cache_root: Option<PathBuf>) -> Result<Option<CurrentInstall>> {
    let install_root = resolve_cache_root(cache_root)?.join("rules");
    let pointer_path = install_root.join(CURRENT_POINTER_FILENAME);
    if !pointer_path.exists() {
        return Ok(None);
    }
    let body = std::fs::read_to_string(&pointer_path)
        .with_context(|| format!("reading {}", pointer_path.display()))?;
    let pointer: CurrentPointer = serde_json::from_str(&body)
        .with_context(|| format!("parsing {}", pointer_path.display()))?;
    let install_dir = install_root.join(&pointer.version);
    Ok(Some(CurrentInstall {
        version: pointer.version,
        trusted_key_id: pointer.trusted_key_id,
        install_dir,
    }))
}

#[derive(Debug)]
pub(crate) struct CurrentInstall {
    pub(crate) version: String,
    pub(crate) trusted_key_id: String,
    pub(crate) install_dir: PathBuf,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CurrentPointer {
    version: String,
    trusted_key_id: String,
}

fn write_current_pointer(install_root: &Path, version: &str, trusted_key_id: &str) -> Result<()> {
    let pointer = CurrentPointer {
        version: version.to_string(),
        trusted_key_id: trusted_key_id.to_string(),
    };
    let body = serde_json::to_vec_pretty(&pointer).context("serialising current pointer")?;
    let path = install_root.join(CURRENT_POINTER_FILENAME);
    std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn resolve_cache_root(override_dir: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(dir) = override_dir {
        return Ok(dir);
    }
    let base = dirs::cache_dir().ok_or_else(|| {
        anyhow!("could not determine cache directory; pass --cache-dir explicitly")
    })?;
    Ok(base.join("skill-veil"))
}

/// Resolve the latest published release tag by following the GitHub
/// `releases/latest` redirect. We do NOT hit the JSON API to keep the
/// request unauthenticated and avoid the 60/h anonymous quota for
/// users who don't set a token.
fn resolve_latest_version() -> Result<String> {
    let url = "https://github.com/seifreed/skill-veil-rules/releases/latest";
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(30))
        .redirects(0)
        .build();
    let resp = agent
        .get(url)
        .set(
            "User-Agent",
            concat!("skill-veil/", env!("CARGO_PKG_VERSION")),
        )
        .call();
    // Redirect surfaces as `Status(302, ...)` with `redirects(0)`.
    let location = match resp {
        Ok(r) => r.header("location").map(str::to_string),
        Err(ureq::Error::Status(_, r)) => r.header("location").map(str::to_string),
        Err(ureq::Error::Transport(t)) => {
            anyhow::bail!("transport error resolving latest release: {t}")
        }
    };
    let location = location.ok_or_else(|| {
        anyhow!("GitHub did not return a Location header when resolving latest release at {url}")
    })?;
    // Format: https://github.com/seifreed/skill-veil-rules/releases/tag/v0.1.0
    let tag = location
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("could not parse tag from redirect: {location}"))?;
    Ok(tag.to_string())
}

fn validate_version_string(v: &str) -> Result<()> {
    let bytes = v.as_bytes();
    if bytes.is_empty() || bytes[0] != b'v' {
        anyhow::bail!("version `{v}` must start with `v` (e.g. v0.1.0)");
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        anyhow::bail!("version `{v}` must contain only [A-Za-z0-9.-_] — refusing to embed in URL");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_version_accepts_canonical_tags() {
        for v in ["v0.1.0", "v1.2.3", "v0.1.0-rc.1", "v10.20.30"] {
            validate_version_string(v).unwrap_or_else(|e| panic!("{v} should be valid: {e}"));
        }
    }

    #[test]
    fn validate_version_rejects_url_smuggling() {
        for bad in [
            "",
            "0.1.0",
            "v0.1.0/../etc",
            "v0.1.0?x=1",
            "v0.1.0&q=z",
            "v 0.1.0",
        ] {
            assert!(
                validate_version_string(bad).is_err(),
                "{bad} must be rejected"
            );
        }
    }

    /// Contract: when no `init` has run, `current_install` returns
    /// `None` rather than erroring. The CLI treats this as "scanner
    /// will fall back to embedded rules" instead of a fatal error.
    #[test]
    fn current_install_is_none_when_pointer_missing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let result = current_install(Some(tmp.path().to_path_buf())).unwrap();
        assert!(result.is_none());
    }

    /// Contract: after `init` writes the pointer, `current_install`
    /// surfaces it. The pointer payload is JSON so external tooling
    /// can read it (e.g. CI dashboards) without invoking the binary.
    #[test]
    fn write_and_read_pointer_round_trip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install_root = tmp.path().join("rules");
        std::fs::create_dir_all(&install_root).unwrap();
        write_current_pointer(&install_root, "v0.1.0", "skill-veil-rules-2026").unwrap();
        let install = current_install(Some(tmp.path().to_path_buf()))
            .unwrap()
            .expect("pointer must be readable after write");
        assert_eq!(install.version, "v0.1.0");
        assert_eq!(install.trusted_key_id, "skill-veil-rules-2026");
        assert_eq!(install.install_dir, install_root.join("v0.1.0"));
    }
}
