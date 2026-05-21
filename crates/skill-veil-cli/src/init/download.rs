//! HTTP download of `skill-veil-rules` release assets.
//!
//! Uses `ureq` (already in the workspace) for synchronous HTTP, mirroring
//! the existing VT and PromptIntel clients. The download path is
//! intentionally narrow: fetch a small JSON document and a base64
//! signature directly into memory; stream the tarball into a bounded
//! temp file so a hostile gateway cannot exhaust memory by streaming an
//! unbounded body.

use anyhow::{bail, Context, Result};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

const USER_AGENT: &str = concat!("skill-veil/", env!("CARGO_PKG_VERSION"), " (+rules-init)");
const HTTP_TIMEOUT_SECS: u64 = 60;

/// Hard cap on how big the manifest+signature can be. The real
/// manifest is a few KB; allowing 1 MiB still lets future schema
/// growth fit comfortably while preventing a 1 GiB JSON body from
/// pinning memory.
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

/// Hard cap on the tarball size. The current rules pack is ~50 KB;
/// 64 MiB leaves room for years of growth (YARA rules, IOC feeds) while
/// blocking a hostile mirror from streaming an exhausting body. Bump
/// this if a release legitimately needs more, but never silently.
const MAX_TARBALL_BYTES: u64 = 64 * 1024 * 1024;

/// Absolute URLs of the three release assets to fetch. Resolved up-front
/// so the caller can audit which endpoints will be hit.
#[derive(Debug, Clone)]
pub(crate) struct ReleaseAssets {
    pub(crate) version: String,
    pub(crate) manifest_url: String,
    pub(crate) signature_url: String,
    pub(crate) tarball_url: String,
}

impl ReleaseAssets {
    /// Build the canonical asset URLs for `version` (e.g. `v0.1.0`)
    /// against the public `skill-veil-rules` release feed.
    pub(crate) fn for_version(version: &str) -> Self {
        let base =
            format!("https://github.com/seifreed/skill-veil-rules/releases/download/{version}");
        Self {
            version: version.to_string(),
            manifest_url: format!("{base}/manifest.json"),
            signature_url: format!("{base}/manifest.json.sig"),
            tarball_url: format!("{base}/skill-veil-rules-{version}.tar.gz"),
        }
    }
}

pub(crate) struct Downloaded {
    pub(crate) manifest_bytes: Vec<u8>,
    pub(crate) signature_bytes: Vec<u8>,
    pub(crate) tarball_path: PathBuf,
}

pub(crate) fn fetch_release(assets: &ReleaseAssets, staging_dir: &Path) -> Result<Downloaded> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .build();

    tracing::info!(version = %assets.version, "fetching manifest.json");
    let manifest_bytes = get_bounded(&agent, &assets.manifest_url, MAX_MANIFEST_BYTES)
        .with_context(|| format!("fetching {}", assets.manifest_url))?;

    tracing::info!(version = %assets.version, "fetching manifest.json.sig");
    let signature_bytes = get_bounded(&agent, &assets.signature_url, MAX_MANIFEST_BYTES)
        .with_context(|| format!("fetching {}", assets.signature_url))?;

    let tarball_path = staging_dir.join("release.tar.gz");
    tracing::info!(
        version = %assets.version,
        url = %assets.tarball_url,
        dest = %tarball_path.display(),
        "fetching release tarball"
    );
    stream_to_file(
        &agent,
        &assets.tarball_url,
        &tarball_path,
        MAX_TARBALL_BYTES,
    )
    .with_context(|| format!("fetching {}", assets.tarball_url))?;

    Ok(Downloaded {
        manifest_bytes,
        signature_bytes,
        tarball_path,
    })
}

fn get_bounded(agent: &ureq::Agent, url: &str, cap: u64) -> Result<Vec<u8>> {
    let resp = agent
        .get(url)
        .set("User-Agent", USER_AGENT)
        .set("Accept", "application/octet-stream")
        .call()
        .map_err(|e| anyhow::anyhow!("HTTP error: {e}"))?;

    let status = resp.status();
    if !(200..300).contains(&status) {
        bail!("HTTP {status} from {url}");
    }

    let mut body = Vec::with_capacity(8 * 1024);
    resp.into_reader()
        .take(cap + 1)
        .read_to_end(&mut body)
        .with_context(|| format!("reading {url}"))?;
    if body.len() as u64 > cap {
        bail!(
            "{url} body exceeded the {} byte cap — refusing to load potentially unbounded content",
            cap
        );
    }
    Ok(body)
}

fn stream_to_file(agent: &ureq::Agent, url: &str, dest: &Path, cap: u64) -> Result<()> {
    let resp = agent
        .get(url)
        .set("User-Agent", USER_AGENT)
        .set("Accept", "application/octet-stream")
        .call()
        .map_err(|e| anyhow::anyhow!("HTTP error: {e}"))?;

    let status = resp.status();
    if !(200..300).contains(&status) {
        bail!("HTTP {status} from {url}");
    }

    stream_reader_to_file(resp.into_reader(), url, dest, cap)
}

fn stream_reader_to_file(reader: impl Read, url: &str, dest: &Path, cap: u64) -> Result<()> {
    let parent = dest
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no parent directory", dest.display()))?;
    ensure_real_dir(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating temp file under {}", parent.display()))?;
    let mut reader = reader.take(cap + 1);
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
        if written > cap {
            bail!("{url} body exceeded the {} byte cap mid-stream", cap);
        }
        file.write_all(&buf[..n])
            .with_context(|| format!("writing temp file for {}", dest.display()))?;
    }
    file.flush()
        .with_context(|| format!("flushing temp file for {}", dest.display()))?;
    file.as_file_mut()
        .sync_all()
        .with_context(|| format!("syncing temp file for {}", dest.display()))?;
    file.persist(dest)
        .map_err(|err| err.error)
        .with_context(|| format!("renaming temp file to {}", dest.display()))?;
    Ok(())
}

fn ensure_real_dir(path: &Path) -> Result<()> {
    if std::fs::symlink_metadata(path)
        .map(|meta| meta.is_dir() && !meta.file_type().is_symlink())
        .unwrap_or(false)
    {
        Ok(())
    } else {
        anyhow::bail!("{} is not a real directory", path.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: asset URLs are derived deterministically from the
    /// version. Pin the format so an accidental edit (e.g. someone
    /// trimming the leading `v`) shows up as a test failure rather
    /// than a silent 404 at runtime.
    #[test]
    fn release_assets_url_format_is_pinned() {
        let assets = ReleaseAssets::for_version("v0.1.0");
        assert_eq!(
            assets.manifest_url,
            "https://github.com/seifreed/skill-veil-rules/releases/download/v0.1.0/manifest.json"
        );
        assert_eq!(
            assets.signature_url,
            "https://github.com/seifreed/skill-veil-rules/releases/download/v0.1.0/manifest.json.sig"
        );
        assert_eq!(
            assets.tarball_url,
            "https://github.com/seifreed/skill-veil-rules/releases/download/v0.1.0/skill-veil-rules-v0.1.0.tar.gz"
        );
    }

    /// # Contract
    ///
    /// Tarball streaming replaces a symlink at the destination path as
    /// a directory entry. It must not follow the link and overwrite
    /// the target outside the staging directory.
    #[cfg(unix)]
    #[test]
    fn stream_reader_to_file_replaces_symlink_without_touching_target() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside.tar.gz");
        let dest = dir.path().join("release.tar.gz");
        std::fs::write(&outside, b"keep").unwrap();
        std::os::unix::fs::symlink(&outside, &dest).unwrap();

        stream_reader_to_file(
            std::io::Cursor::new(b"fresh".to_vec()),
            "test-url",
            &dest,
            1024,
        )
        .unwrap();

        assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
        assert!(!std::fs::symlink_metadata(&dest)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(&dest).unwrap(), b"fresh");
    }
}
