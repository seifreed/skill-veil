//! NOVA rule pack download + install.
//!
//! NOVA rules live at <https://github.com/Nova-Hunting/nova-rules>.
//! Unlike `skill-veil-rules`, the NOVA repo does not publish signed
//! manifests, so our trust anchor is `git`'s commit-SHA addressability:
//! we pin a specific commit, fetch it via the immutable
//! `archive/<sha>.tar.gz` URL, and record the SHA in
//! `nova-current.json` so subsequent updates know what to compare
//! against.
//!
//! The tarball is also SHA-256'd at install time; the digest is
//! recorded in `nova-current.json` so a future install can detect
//! upstream rewrites of an old commit (theoretical but cheap to
//! defend).

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

const USER_AGENT: &str = concat!("skill-veil/", env!("CARGO_PKG_VERSION"), " (+nova-init)");
const HTTP_TIMEOUT_SECS: u64 = 60;

/// Hard cap on the NOVA tarball size. The current pack is ~50 KB; 16
/// MiB leaves room for years of growth while blocking a hostile mirror
/// from streaming an exhausting body.
const MAX_TARBALL_BYTES: u64 = 16 * 1024 * 1024;

/// Public alias for the GitHub commit-SHA pin we use as the trust
/// anchor. Stored in `nova-current.json` and surfaced in the
/// `rules status` output.
pub(crate) type NovaSha = String;

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub(crate) struct NovaInstallPointer {
    pub(crate) commit_sha: NovaSha,
    /// SHA-256 of the downloaded tarball, hex-encoded. Lets a later
    /// install detect a rewritten upstream commit (rare but cheap to
    /// guard against).
    pub(crate) tarball_sha256: String,
    /// Number of `.nov` files extracted into the install dir.
    pub(crate) file_count: usize,
}

/// Filename of the per-cache pointer recording the active NOVA pin.
pub(crate) const NOVA_POINTER_FILENAME: &str = "nova-current.json";

/// Resolve the latest commit SHA on the upstream `main` branch.
/// Hits the GitHub REST API anonymously (60/h quota); the lookup is
/// only invoked when the caller asks for "latest" (no explicit pin).
pub(crate) fn resolve_latest_sha() -> Result<NovaSha> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .build();
    let resp = agent
        .get("https://api.github.com/repos/Nova-Hunting/nova-rules/commits/HEAD")
        .set("User-Agent", USER_AGENT)
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| anyhow!("HTTP error resolving NOVA latest SHA: {e}"))?;
    let status = resp.status();
    if !(200..300).contains(&status) {
        bail!("GitHub API returned HTTP {status} resolving NOVA latest SHA");
    }
    let body = resp
        .into_string()
        .context("reading GitHub API response body")?;
    let v: serde_json::Value = serde_json::from_str(&body).context("parsing GitHub commit JSON")?;
    let sha = v
        .get("sha")
        .and_then(|s| s.as_str())
        .ok_or_else(|| anyhow!("GitHub commit JSON had no `sha` field"))?
        .to_string();
    if sha.len() != 40 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("GitHub returned an unexpected SHA shape: `{sha}` (expected 40-char hex)");
    }
    Ok(sha)
}

/// Download the NOVA tarball pinned to `sha` into `staging_dir` and
/// extract it. Returns the install-pointer payload + the path the
/// tarball was extracted into.
pub(crate) fn download_and_extract(
    sha: &NovaSha,
    staging_dir: &Path,
) -> Result<(NovaInstallPointer, PathBuf)> {
    validate_sha_shape(sha)?;
    let url = format!("https://github.com/Nova-Hunting/nova-rules/archive/{sha}.tar.gz");

    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .build();

    tracing::info!(sha = %sha, url = %url, "fetching NOVA rule pack");
    let resp = agent
        .get(&url)
        .set("User-Agent", USER_AGENT)
        .set("Accept", "application/octet-stream")
        .call()
        .map_err(|e| anyhow!("HTTP error fetching NOVA tarball: {e}"))?;
    let status = resp.status();
    if !(200..300).contains(&status) {
        bail!("HTTP {status} from {url}");
    }

    let tarball_path = staging_dir.join("nova.tar.gz");
    let mut hasher = Sha256::new();
    {
        let mut file = std::fs::File::create(&tarball_path)
            .with_context(|| format!("creating {}", tarball_path.display()))?;
        let mut reader = resp.into_reader().take(MAX_TARBALL_BYTES + 1);
        let mut written: u64 = 0;
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = reader
                .read(&mut buf)
                .with_context(|| format!("streaming {url}"))?;
            if n == 0 {
                break;
            }
            written += n as u64;
            if written > MAX_TARBALL_BYTES {
                let _ = std::fs::remove_file(&tarball_path);
                bail!("{url} body exceeded the {MAX_TARBALL_BYTES} byte cap mid-stream");
            }
            hasher.update(&buf[..n]);
            file.write_all(&buf[..n])
                .with_context(|| format!("writing {}", tarball_path.display()))?;
        }
        file.flush().ok();
    }
    let tarball_sha256 = hex::encode(hasher.finalize());

    // Reuse the hardened extractor we built for skill-veil-rules.
    let extract_root = staging_dir.join("nova-extract");
    super::extract::extract_into(&tarball_path, &extract_root)
        .context("extracting NOVA tarball")?;

    // GitHub archive layout puts everything inside a top-level
    // `nova-rules-<sha>/` directory. Locate it (there should be
    // exactly one) and record file count.
    let inner =
        locate_unique_subdir(&extract_root).context("locating extracted NOVA root directory")?;
    let file_count = count_nov_files(&inner);

    Ok((
        NovaInstallPointer {
            commit_sha: sha.clone(),
            tarball_sha256,
            file_count,
        },
        inner,
    ))
}

fn locate_unique_subdir(root: &Path) -> Result<PathBuf> {
    let mut subdirs: Vec<PathBuf> = std::fs::read_dir(root)?
        .filter_map(Result::ok)
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.path())
        .collect();
    if subdirs.len() != 1 {
        bail!(
            "expected exactly one top-level dir in NOVA archive, got {}",
            subdirs.len()
        );
    }
    Ok(subdirs.pop().unwrap())
}

fn count_nov_files(root: &Path) -> usize {
    walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("nov"))
        .count()
}

fn validate_sha_shape(sha: &str) -> Result<()> {
    if sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        bail!("NOVA commit pin `{sha}` is not a 40-char hex SHA — refusing to embed in URL")
    }
}

/// Read the persisted NOVA install pointer from `<install_root>`
/// (the same directory `init` writes into for skill-veil-rules).
pub(crate) fn load_pointer(install_root: &Path) -> Result<Option<NovaInstallPointer>> {
    let path = install_root.join(NOVA_POINTER_FILENAME);
    if !path.exists() {
        return Ok(None);
    }
    let body =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let pointer: NovaInstallPointer =
        serde_json::from_str(&body).with_context(|| format!("parsing {}", path.display()))?;
    validate_sha_shape(&pointer.commit_sha)
        .with_context(|| format!("validating commit_sha in {}", path.display()))?;
    validate_sha256_hex(&pointer.tarball_sha256)
        .with_context(|| format!("validating tarball_sha256 in {}", path.display()))?;
    Ok(Some(pointer))
}

pub(crate) fn write_pointer(install_root: &Path, pointer: &NovaInstallPointer) -> Result<()> {
    validate_sha_shape(&pointer.commit_sha).context("validating NOVA pointer commit_sha")?;
    validate_sha256_hex(&pointer.tarball_sha256)
        .context("validating NOVA pointer tarball_sha256")?;
    let body = serde_json::to_vec_pretty(pointer).context("serialising NOVA pointer")?;
    let path = install_root.join(NOVA_POINTER_FILENAME);
    std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn validate_sha256_hex(value: &str) -> Result<()> {
    if value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        bail!("NOVA tarball SHA-256 `{value}` is not a 64-char hex digest")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: `validate_sha_shape` rejects anything that isn't a
    /// 40-char hex string. URL injection through a malformed SHA
    /// would let a hostile pin redirect the download elsewhere.
    #[test]
    fn validate_sha_shape_rejects_url_smuggling() {
        for bad in [
            "",
            "deadbeef",                                   // too short
            "../../etc/passwd",                           // path
            "9249cf49dce2b30550bc23d00a36ec64d42932d0/x", // trailing path
            "9249cf49dce2b30550bc23d00a36ec64d42932dG",   // non-hex
            "9249cf49dce2b30550bc23d00a36ec64d42932d0a",  // too long
        ] {
            assert!(validate_sha_shape(bad).is_err(), "{bad:?} must be rejected");
        }
        // Sanity: a real SHA passes.
        assert!(validate_sha_shape("9249cf49dce2b30550bc23d00a36ec64d42932d0").is_ok());
    }

    /// Contract: pointer round-trips through disk so `rules status`
    /// can read what `init` wrote.
    #[test]
    fn pointer_round_trip() {
        let dir = tempfile::TempDir::new().unwrap();
        let p = NovaInstallPointer {
            commit_sha: "9249cf49dce2b30550bc23d00a36ec64d42932d0".into(),
            tarball_sha256: "0".repeat(64),
            file_count: 42,
        };
        write_pointer(dir.path(), &p).unwrap();
        let loaded = load_pointer(dir.path()).unwrap().expect("must round-trip");
        assert_eq!(loaded.commit_sha, p.commit_sha);
        assert_eq!(loaded.tarball_sha256, p.tarball_sha256);
        assert_eq!(loaded.file_count, p.file_count);
    }

    /// Contract: missing pointer is `Ok(None)` not an error — an
    /// operator who hasn't run `init` for NOVA yet should see "not
    /// installed", not a runtime error.
    #[test]
    fn missing_pointer_is_ok_none() {
        let dir = tempfile::TempDir::new().unwrap();
        assert!(load_pointer(dir.path()).unwrap().is_none());
    }

    /// Contract: a persisted pointer cannot turn `commit_sha` into a
    /// filesystem path segment.
    #[test]
    fn load_pointer_rejects_path_like_commit_sha() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(NOVA_POINTER_FILENAME);
        let body = format!(
            r#"{{"commit_sha":"9249cf49dce2b30550bc23d00a36ec64d42932d0/../../evil","tarball_sha256":"{}","file_count":1}}"#,
            "0".repeat(64)
        );
        std::fs::write(&path, body).unwrap();

        let err = load_pointer(dir.path()).expect_err("path-like commit_sha must be rejected");

        assert!(format!("{err:#}").contains("not a 40-char hex SHA"));
    }

    /// Contract: persisted tarball digests keep their SHA-256 shape.
    #[test]
    fn load_pointer_rejects_malformed_tarball_sha256() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(NOVA_POINTER_FILENAME);
        std::fs::write(
            &path,
            br#"{"commit_sha":"9249cf49dce2b30550bc23d00a36ec64d42932d0","tarball_sha256":"abc123","file_count":1}"#,
        )
        .unwrap();

        let err = load_pointer(dir.path()).expect_err("bad tarball digest must be rejected");

        assert!(format!("{err:#}").contains("not a 64-char hex digest"));
    }
}
