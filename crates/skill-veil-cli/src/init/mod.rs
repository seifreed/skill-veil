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
pub(crate) mod nova;
pub(crate) mod update_check;
mod verify;

use anyhow::{anyhow, Context, Result};
use std::fs::Metadata;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub(crate) use download::ReleaseAssets;

/// Filename of the small JSON pointer that marks which installed
/// version is "current". Read by `default_external_rule_dirs()` and
/// `skill-veil rules status`.
pub(crate) const CURRENT_POINTER_FILENAME: &str = "current.json";
pub(crate) const MAX_INSTALL_POINTER_BYTES: u64 = 64 * 1024;

/// Outcome of a successful `init` run, returned to the CLI for human
/// rendering. Carries both the skill-veil-rules side and the NOVA
/// side; either may be `None` if that source was skipped.
#[derive(Debug)]
pub(crate) struct InitOutcome {
    pub(crate) version: String,
    pub(crate) trusted_key_id: &'static str,
    pub(crate) install_dir: PathBuf,
    pub(crate) file_count: usize,
    pub(crate) nova: Option<NovaOutcome>,
}

#[derive(Debug)]
pub(crate) struct NovaOutcome {
    pub(crate) commit_sha: String,
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
    let install_root = prepare_install_root(&cache_root)?;

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
    remove_existing_install_dir(&install_dir)?;
    std::fs::rename(&extract_root, &install_dir).with_context(|| {
        format!(
            "atomic rename {} -> {}",
            extract_root.display(),
            install_dir.display()
        )
    })?;

    write_current_pointer(&install_root, &version, trusted_key_id)?;

    let file_count = manifest.files.len();

    // NOVA side. Failures here MUST NOT abort the skill-veil-rules
    // install (which already succeeded); we surface them as a
    // warning and let the operator re-run `rules update`. NOVA is
    // an additional rule source, not a hard dependency of the
    // scanner.
    let nova_outcome = match install_nova_pinned_to_latest(&install_root) {
        Ok(out) => Some(out),
        Err(err) => {
            tracing::warn!(
                "NOVA install failed (skill-veil-rules install OK): {err:#}; \
                 retry with `skill-veil rules update`"
            );
            None
        }
    };

    Ok(InitOutcome {
        version,
        trusted_key_id,
        install_dir,
        file_count,
        nova: nova_outcome,
    })
}

/// Resolve the latest NOVA commit SHA, download the matching
/// tarball, verify its size + SHA-256, extract it, and atomically
/// rename into `<install_root>/nova-<sha>/`.
pub(crate) fn install_nova_pinned_to_latest(install_root: &Path) -> Result<NovaOutcome> {
    let sha = nova::resolve_latest_sha().context("resolving latest NOVA commit SHA")?;
    install_nova_pinned_to(install_root, &sha)
}

pub(crate) fn install_nova_pinned_to(install_root: &Path, sha: &str) -> Result<NovaOutcome> {
    let existing_pointer =
        nova::load_pointer(install_root).context("loading existing NOVA install pointer")?;
    let staging = tempfile::tempdir_in(install_root)
        .with_context(|| format!("creating staging dir under {}", install_root.display()))?;
    let (pointer, extracted_root) = nova::download_and_extract(&sha.to_string(), staging.path())
        .context("downloading NOVA tarball")?;
    nova::reject_tarball_rewrite(existing_pointer.as_ref(), &pointer)
        .context("checking NOVA tarball rewrite guard")?;

    let install_dir = install_root.join(format!("nova-{sha}"));
    remove_existing_install_dir(&install_dir)?;
    std::fs::rename(&extracted_root, &install_dir).with_context(|| {
        format!(
            "atomic rename {} -> {}",
            extracted_root.display(),
            install_dir.display()
        )
    })?;
    nova::write_pointer(install_root, &pointer)?;
    Ok(NovaOutcome {
        commit_sha: pointer.commit_sha,
        install_dir,
        file_count: pointer.file_count,
    })
}

/// Render outcome details for `skill-veil rules status`. Carries
/// both the skill-veil-rules install (`Some` when an `init` has
/// completed for it) and the NOVA install (`Some` when an `init` /
/// `rules update` has run NOVA download successfully).
pub(crate) fn current_install(cache_root: Option<PathBuf>) -> Result<CombinedInstall> {
    let cache_root = resolve_cache_root(cache_root)?;
    let Some(install_root) = install_root_for_read(&cache_root)? else {
        return Ok(CombinedInstall {
            skill_veil: None,
            nova: None,
        });
    };
    let skill_veil = read_skill_veil_install(&install_root)?;
    let nova = read_nova_install(&install_root)?;
    Ok(CombinedInstall { skill_veil, nova })
}

fn read_skill_veil_install(install_root: &Path) -> Result<Option<CurrentInstall>> {
    let pointer_path = install_root.join(CURRENT_POINTER_FILENAME);
    if is_missing_path(&pointer_path)? {
        return Ok(None);
    }
    let body = read_install_pointer_file(&pointer_path)?;
    let pointer: CurrentPointer = serde_json::from_str(&body)
        .with_context(|| format!("parsing {}", pointer_path.display()))?;
    validate_version_string(&pointer.version)
        .with_context(|| format!("validating {}", pointer_path.display()))?;
    validate_trusted_key_id(&pointer.trusted_key_id)
        .with_context(|| format!("validating trusted_key_id in {}", pointer_path.display()))?;
    let install_dir = install_root.join(&pointer.version);
    ensure_real_install_dir(&install_dir)?;
    Ok(Some(CurrentInstall {
        version: pointer.version,
        trusted_key_id: pointer.trusted_key_id,
        install_dir,
    }))
}

pub(crate) fn read_install_pointer_file(path: &Path) -> Result<String> {
    read_file_to_string_with_cap(path, MAX_INSTALL_POINTER_BYTES)
        .with_context(|| format!("reading {}", path.display()))
}

fn read_file_to_string_with_cap(path: &Path, cap: u64) -> io::Result<String> {
    let path_meta = std::fs::symlink_metadata(path)?;
    if !path_meta.is_file() || path_meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing to read non-regular install pointer {}",
                path.display()
            ),
        ));
    }
    if !has_single_hardlink(&path_meta) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing to read install pointer {}: file has multiple hard links",
                path.display()
            ),
        ));
    }

    let file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
    if !opened_file_matches_path(&meta, &path_meta) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing to read swapped install pointer {}",
                path.display()
            ),
        ));
    }
    if meta.len() > cap {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "refusing to read {}: size {} exceeds limit {}",
                path.display(),
                meta.len(),
                cap
            ),
        ));
    }

    let mut bytes = Vec::with_capacity(usize::try_from(meta.len().min(cap)).unwrap_or(0));
    let mut limited = file.take(cap.saturating_add(1));
    limited.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "refusing to read {}: size exceeds limit {}",
                path.display(),
                cap
            ),
        ));
    }
    String::from_utf8(bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn read_nova_install(install_root: &Path) -> Result<Option<NovaInstallSnapshot>> {
    let Some(pointer) = nova::load_pointer(install_root)? else {
        return Ok(None);
    };
    let install_dir = install_root.join(format!("nova-{}", pointer.commit_sha));
    ensure_real_install_dir(&install_dir)?;
    Ok(Some(NovaInstallSnapshot {
        commit_sha: pointer.commit_sha,
        tarball_sha256: pointer.tarball_sha256,
        install_dir,
        file_count: pointer.file_count,
    }))
}

#[derive(Debug)]
pub(crate) struct CombinedInstall {
    pub(crate) skill_veil: Option<CurrentInstall>,
    pub(crate) nova: Option<NovaInstallSnapshot>,
}

#[derive(Debug)]
pub(crate) struct CurrentInstall {
    pub(crate) version: String,
    pub(crate) trusted_key_id: String,
    pub(crate) install_dir: PathBuf,
}

#[derive(Debug)]
pub(crate) struct NovaInstallSnapshot {
    pub(crate) commit_sha: String,
    pub(crate) tarball_sha256: String,
    pub(crate) install_dir: PathBuf,
    pub(crate) file_count: usize,
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
    write_install_file_atomic(&path, &body)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

pub(super) fn write_install_file_atomic(path: &Path, body: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", path.display()))?;
    ensure_real_dir(parent)?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating temp file under {}", parent.display()))?;
    tmp.write_all(body)
        .with_context(|| format!("writing temp file under {}", parent.display()))?;
    tmp.as_file_mut()
        .sync_all()
        .with_context(|| format!("syncing temp file under {}", parent.display()))?;
    tmp.persist(path)
        .map_err(|err| err.error)
        .with_context(|| format!("renaming temp file to {}", path.display()))?;
    Ok(())
}

fn remove_existing_install_dir(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            anyhow::bail!(
                "refusing to replace symlinked install path {}",
                path.display()
            )
        }
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(path)
            .with_context(|| format!("removing existing install {}", path.display())),
        Ok(_) => anyhow::bail!(
            "refusing to replace non-directory install path {}",
            path.display()
        ),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("stat {}", path.display())),
    }
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

fn ensure_real_install_dir(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            anyhow::bail!("{} is a symlink", path.display())
        }
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => anyhow::bail!("{} is not an installed rules directory", path.display()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            anyhow::bail!("{} is missing", path.display())
        }
        Err(err) => Err(err).with_context(|| format!("stat {}", path.display())),
    }
}

pub(super) fn is_missing_path(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(err) => Err(err).with_context(|| format!("stat {}", path.display())),
    }
}

#[cfg(unix)]
fn has_single_hardlink(meta: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.nlink() == 1
}

#[cfg(not(unix))]
fn has_single_hardlink(_meta: &Metadata) -> bool {
    true
}

#[cfg(unix)]
fn opened_file_matches_path(opened: &Metadata, path_meta: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    opened.dev() == path_meta.dev() && opened.ino() == path_meta.ino()
}

#[cfg(not(unix))]
fn opened_file_matches_path(_opened: &Metadata, _path_meta: &Metadata) -> bool {
    true
}

fn create_install_root(install_root: &Path) -> Result<()> {
    crate::util::secure_fs::create_dir_secure(install_root)
        .with_context(|| format!("creating install root {}", install_root.display()))
}

fn prepare_install_root(cache_root: &Path) -> Result<PathBuf> {
    crate::util::secure_fs::create_dir_secure(cache_root)
        .with_context(|| format!("creating cache root {}", cache_root.display()))?;
    let install_root = cache_root.join("rules");
    create_install_root(&install_root)?;
    Ok(install_root)
}

fn install_root_for_read(cache_root: &Path) -> Result<Option<PathBuf>> {
    if !real_dir_exists_for_read(cache_root)? {
        return Ok(None);
    }
    let install_root = cache_root.join("rules");
    if !real_dir_exists_for_read(&install_root)? {
        return Ok(None);
    }
    Ok(Some(install_root))
}

fn real_dir_exists_for_read(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            anyhow::bail!("{} is a symlink", path.display())
        }
        Ok(meta) if meta.is_dir() => Ok(true),
        Ok(_) => anyhow::bail!("{} is not a directory", path.display()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| format!("stat {}", path.display())),
    }
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

fn validate_trusted_key_id(id: &str) -> Result<()> {
    if id.is_empty()
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        anyhow::bail!(
            "trusted_key_id must contain only [A-Za-z0-9.-_] — refusing to render pointer"
        );
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
    /// a `CombinedInstall` whose `skill_veil` AND `nova` fields are
    /// both `None`. Treated by the CLI as "scanner will fall back to
    /// embedded rules" instead of a fatal error.
    #[test]
    fn current_install_is_empty_when_pointers_missing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let result = current_install(Some(tmp.path().to_path_buf())).unwrap();
        assert!(result.skill_veil.is_none());
        assert!(result.nova.is_none());
    }

    /// # Contract
    ///
    /// A missing cache root is a clean "not installed" state for
    /// read-only status checks. `rules status` and scan startup must not
    /// create cache directories just to discover that no init has run.
    #[test]
    fn current_install_is_empty_when_cache_root_missing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let missing = tmp.path().join("missing-cache");

        let result = current_install(Some(missing)).unwrap();

        assert!(result.skill_veil.is_none());
        assert!(result.nova.is_none());
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
    }

    /// # Contract
    ///
    /// Read-only install discovery must reject a symlink supplied as the
    /// cache root rather than loading rule pointers from the symlink
    /// target.
    #[cfg(unix)]
    #[test]
    fn current_install_rejects_symlinked_cache_root() {
        let tmp = tempfile::TempDir::new().unwrap();
        let outside = tmp.path().join("outside");
        let link = tmp.path().join("cache");
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        let err = current_install(Some(link)).unwrap_err();

        assert!(format!("{err:#}").contains("symlink"));
    }

    /// # Contract
    ///
    /// Read-only install discovery must reject a symlinked `rules`
    /// directory before looking for `current.json` or `nova-current.json`.
    #[cfg(unix)]
    #[test]
    fn current_install_rejects_symlinked_rules_root() {
        let tmp = tempfile::TempDir::new().unwrap();
        let outside = tmp.path().join("outside-rules");
        let link = tmp.path().join("rules");
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        let err = current_install(Some(tmp.path().to_path_buf())).unwrap_err();

        assert!(format!("{err:#}").contains("symlink"));
    }

    /// Contract: after `init` writes the pointer, the skill-veil
    /// side of `current_install` surfaces it. The pointer payload is
    /// JSON so external tooling (CI dashboards) can read it without
    /// invoking the binary.
    #[test]
    fn write_and_read_skill_veil_pointer_round_trip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install_root = tmp.path().join("rules");
        let version_dir = install_root.join("v0.1.0");
        std::fs::create_dir_all(&install_root).unwrap();
        std::fs::create_dir_all(&version_dir).unwrap();
        write_current_pointer(&install_root, "v0.1.0", "skill-veil-rules-2026").unwrap();
        let install = current_install(Some(tmp.path().to_path_buf())).unwrap();
        let sv = install
            .skill_veil
            .expect("skill-veil pointer must be readable after write");
        assert_eq!(sv.version, "v0.1.0");
        assert_eq!(sv.trusted_key_id, "skill-veil-rules-2026");
        assert_eq!(sv.install_dir, version_dir);
        // NOVA side is independent — must remain absent until its
        // own pointer is written.
        assert!(install.nova.is_none());
    }

    /// # Contract
    ///
    /// `current_install` must reject a pointer whose version directory is
    /// missing. A dangling pointer is corrupted install state, not a
    /// completed rule-pack install.
    #[test]
    fn current_install_rejects_missing_skill_veil_version_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install_root = tmp.path().join("rules");
        std::fs::create_dir_all(&install_root).unwrap();
        write_current_pointer(&install_root, "v0.1.0", "skill-veil-rules-2026").unwrap();

        let err = current_install(Some(tmp.path().to_path_buf()))
            .expect_err("missing version directory must be rejected");

        assert!(format!("{err:#}").contains("missing"));
    }

    /// # Contract
    ///
    /// `current_install` must reject a symlinked skill-veil-rules version
    /// directory rather than reporting it as an installed trusted pack.
    #[cfg(unix)]
    #[test]
    fn current_install_rejects_symlinked_skill_veil_version_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install_root = tmp.path().join("rules");
        let outside = tmp.path().join("outside-version");
        let version_dir = install_root.join("v0.1.0");
        std::fs::create_dir_all(&install_root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &version_dir).unwrap();
        write_current_pointer(&install_root, "v0.1.0", "skill-veil-rules-2026").unwrap();

        let err = current_install(Some(tmp.path().to_path_buf()))
            .expect_err("symlinked version directory must be rejected");

        assert!(format!("{err:#}").contains("symlink"));
    }

    /// # Contract
    ///
    /// Installed rule-pack pointers under the byte cap MUST read
    /// normally. The cap protects the cache lookup path without
    /// changing the JSON pointer format.
    #[test]
    fn install_pointer_read_accepts_valid_json_under_cap() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join(CURRENT_POINTER_FILENAME);
        std::fs::write(
            &path,
            br#"{"version":"v0.1.0","trusted_key_id":"skill-veil-rules-2026"}"#,
        )
        .unwrap();

        let body = read_install_pointer_file(&path).unwrap();

        assert!(body.contains("v0.1.0"));
    }

    /// # Contract
    ///
    /// Installed rule-pack pointer reads MUST reject oversized files
    /// before JSON parsing, so a poisoned cache pointer cannot force
    /// unbounded memory allocation during `rules status`.
    #[test]
    fn install_pointer_read_rejects_oversized_json() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join(CURRENT_POINTER_FILENAME);
        let oversized_len = usize::try_from(MAX_INSTALL_POINTER_BYTES).unwrap() + 1;
        std::fs::write(&path, vec![b'{'; oversized_len]).unwrap();

        let err = read_install_pointer_file(&path).unwrap_err();

        assert!(format!("{err:#}").contains("exceeds limit"));
    }

    /// # Contract
    ///
    /// Installed rule-pack pointer reads only accept regular files.
    /// Symlinks are not valid cache pointers, even when their target is
    /// readable JSON.
    #[cfg(unix)]
    #[test]
    fn install_pointer_read_rejects_symlinked_json() {
        let tmp = tempfile::TempDir::new().unwrap();
        let real = tmp.path().join("real-current.json");
        let link = tmp.path().join(CURRENT_POINTER_FILENAME);
        std::fs::write(
            &real,
            br#"{"version":"v0.1.0","trusted_key_id":"skill-veil-rules-2026"}"#,
        )
        .unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let err = read_install_pointer_file(&link).unwrap_err();

        assert!(format!("{err:#}").contains("non-regular install pointer"));
    }

    /// # Contract
    ///
    /// Installed rule-pack pointer reads only accept files with a
    /// single directory entry. A hardlinked pointer is rejected instead
    /// of reading an inode whose provenance is outside the install root.
    #[cfg(unix)]
    #[test]
    fn install_pointer_read_rejects_hardlinked_json() {
        let tmp = tempfile::TempDir::new().unwrap();
        let real = tmp.path().join("real-current.json");
        let link = tmp.path().join(CURRENT_POINTER_FILENAME);
        std::fs::write(
            &real,
            br#"{"version":"v0.1.0","trusted_key_id":"skill-veil-rules-2026"}"#,
        )
        .unwrap();
        std::fs::hard_link(&real, &link).unwrap();

        let err = read_install_pointer_file(&link).unwrap_err();

        assert!(format!("{err:#}").contains("multiple hard links"));
    }

    /// # Contract
    ///
    /// Writing `current.json` must replace a symlinked directory entry,
    /// not follow it and overwrite the target.
    #[cfg(unix)]
    #[test]
    fn write_current_pointer_replaces_symlink_without_touching_target() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install_root = tmp.path().join("rules");
        let outside = tmp.path().join("outside.json");
        let pointer_path = install_root.join(CURRENT_POINTER_FILENAME);
        std::fs::create_dir(&install_root).unwrap();
        std::fs::write(&outside, b"keep").unwrap();
        std::os::unix::fs::symlink(&outside, &pointer_path).unwrap();

        write_current_pointer(&install_root, "v0.1.0", "skill-veil-rules-2026").unwrap();

        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep");
        assert!(!std::fs::symlink_metadata(&pointer_path)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    /// # Contract
    ///
    /// Existing install-version paths must be real directories before
    /// replacement. A symlink there is rejected instead of removed or
    /// traversed.
    #[cfg(unix)]
    #[test]
    fn remove_existing_install_dir_rejects_symlinked_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        let outside = tmp.path().join("outside");
        let link = tmp.path().join("v0.1.0");
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        let err = remove_existing_install_dir(&link).unwrap_err();

        assert!(format!("{err:#}").contains("symlinked install path"));
        assert!(outside.exists());
    }

    /// Contract: the NOVA pointer round-trips independently of the
    /// skill-veil pointer. An operator who has run `init` once but
    /// never rotated NOVA still gets the skill-veil install reported,
    /// and vice versa.
    #[test]
    fn nova_pointer_round_trips_independently() {
        use super::nova::{write_pointer, NovaInstallPointer};
        let tmp = tempfile::TempDir::new().unwrap();
        let install_root = tmp.path().join("rules");
        let nova_dir = install_root.join("nova-9249cf49dce2b30550bc23d00a36ec64d42932d0");
        std::fs::create_dir_all(&install_root).unwrap();
        std::fs::create_dir_all(&nova_dir).unwrap();
        let pointer = NovaInstallPointer {
            commit_sha: "9249cf49dce2b30550bc23d00a36ec64d42932d0".into(),
            tarball_sha256: "0".repeat(64),
            file_count: 16,
        };
        write_pointer(&install_root, &pointer).unwrap();
        let install = current_install(Some(tmp.path().to_path_buf())).unwrap();
        assert!(install.skill_veil.is_none());
        let nova = install.nova.expect("NOVA pointer must round-trip");
        assert_eq!(nova.commit_sha, pointer.commit_sha);
        assert_eq!(nova.file_count, 16);
    }

    /// # Contract
    ///
    /// `current_install` must reject a symlinked NOVA install directory
    /// rather than reporting it as the installed community rule pack.
    #[cfg(unix)]
    #[test]
    fn current_install_rejects_symlinked_nova_install_dir() {
        use super::nova::{write_pointer, NovaInstallPointer};
        let tmp = tempfile::TempDir::new().unwrap();
        let install_root = tmp.path().join("rules");
        let outside = tmp.path().join("outside-nova");
        let nova_dir = install_root.join("nova-9249cf49dce2b30550bc23d00a36ec64d42932d0");
        std::fs::create_dir_all(&install_root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &nova_dir).unwrap();
        let pointer = NovaInstallPointer {
            commit_sha: "9249cf49dce2b30550bc23d00a36ec64d42932d0".into(),
            tarball_sha256: "0".repeat(64),
            file_count: 16,
        };
        write_pointer(&install_root, &pointer).unwrap();

        let err = current_install(Some(tmp.path().to_path_buf()))
            .expect_err("symlinked NOVA install directory must be rejected");

        assert!(format!("{err:#}").contains("symlink"));
    }

    /// # Contract
    ///
    /// `current_install` must propagate malformed NOVA pointers instead
    /// of reporting NOVA as not installed. A path-shaped commit pin is a
    /// corrupted cache state, not an absent optional rule source.
    #[test]
    fn current_install_rejects_path_like_nova_pointer_commit() {
        use super::nova::NOVA_POINTER_FILENAME;
        let tmp = tempfile::TempDir::new().unwrap();
        let install_root = tmp.path().join("rules");
        std::fs::create_dir_all(&install_root).unwrap();
        let body = format!(
            r#"{{"commit_sha":"9249cf49dce2b30550bc23d00a36ec64d42932d0/../../evil","tarball_sha256":"{}","file_count":1}}"#,
            "0".repeat(64)
        );
        std::fs::write(install_root.join(NOVA_POINTER_FILENAME), body).unwrap();

        let err = current_install(Some(tmp.path().to_path_buf()))
            .expect_err("path-like NOVA commit pin must be rejected");

        assert!(format!("{err:#}").contains("not a 40-char hex SHA"));
    }

    /// # Contract
    ///
    /// `current_install` must reject a symlinked NOVA pointer instead of
    /// treating the optional NOVA source as absent.
    #[cfg(unix)]
    #[test]
    fn current_install_rejects_symlinked_nova_pointer() {
        use super::nova::NOVA_POINTER_FILENAME;
        let tmp = tempfile::TempDir::new().unwrap();
        let install_root = tmp.path().join("rules");
        let outside = tmp.path().join("outside-nova-current.json");
        let pointer_path = install_root.join(NOVA_POINTER_FILENAME);
        std::fs::create_dir_all(&install_root).unwrap();
        std::fs::write(
            &outside,
            format!(
                r#"{{"commit_sha":"9249cf49dce2b30550bc23d00a36ec64d42932d0","tarball_sha256":"{}","file_count":1}}"#,
                "0".repeat(64)
            ),
        )
        .unwrap();
        std::os::unix::fs::symlink(&outside, &pointer_path).unwrap();

        let err = current_install(Some(tmp.path().to_path_buf()))
            .expect_err("symlinked NOVA pointer must be rejected");

        assert!(format!("{err:#}").contains("non-regular install pointer"));
    }

    /// # Contract
    ///
    /// Writing the NOVA pointer follows the same symlink replacement
    /// contract as `current.json`.
    #[cfg(unix)]
    #[test]
    fn nova_pointer_write_replaces_symlink_without_touching_target() {
        use super::nova::{write_pointer, NovaInstallPointer, NOVA_POINTER_FILENAME};
        let tmp = tempfile::TempDir::new().unwrap();
        let install_root = tmp.path().join("rules");
        let outside = tmp.path().join("outside.json");
        let pointer_path = install_root.join(NOVA_POINTER_FILENAME);
        std::fs::create_dir(&install_root).unwrap();
        std::fs::write(&outside, b"keep").unwrap();
        std::os::unix::fs::symlink(&outside, &pointer_path).unwrap();
        let pointer = NovaInstallPointer {
            commit_sha: "9249cf49dce2b30550bc23d00a36ec64d42932d0".into(),
            tarball_sha256: "0".repeat(64),
            file_count: 16,
        };

        write_pointer(&install_root, &pointer).unwrap();

        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep");
        assert!(!std::fs::symlink_metadata(&pointer_path)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    /// # Contract
    ///
    /// The installed rule-pack root must be owner-only on Unix because
    /// `current.json` decides which verified pack the scanner trusts.
    #[cfg(unix)]
    #[test]
    fn create_install_root_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let install_root = tmp.path().join("rules");

        create_install_root(&install_root).unwrap();

        let mode = std::fs::metadata(&install_root)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    /// # Contract
    ///
    /// Install setup must reject a symlink supplied as the cache root
    /// before creating `rules/` under the symlink target.
    #[cfg(unix)]
    #[test]
    fn prepare_install_root_rejects_symlinked_cache_root() {
        let tmp = tempfile::TempDir::new().unwrap();
        let outside = tmp.path().join("outside");
        let link = tmp.path().join("cache");
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        let err = prepare_install_root(&link).unwrap_err();

        assert!(format!("{err:#}").contains("symlink"));
        assert!(!outside.join("rules").exists());
    }

    /// Contract: the skill-veil pointer version must be a release tag,
    /// not a filesystem path.
    #[test]
    fn current_install_rejects_path_like_skill_veil_pointer_version() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install_root = tmp.path().join("rules");
        std::fs::create_dir_all(&install_root).unwrap();
        let pointer_path = install_root.join(CURRENT_POINTER_FILENAME);
        std::fs::write(
            &pointer_path,
            br#"{"version":"v0.1.0/../../evil","trusted_key_id":"test"}"#,
        )
        .unwrap();

        let err = current_install(Some(tmp.path().to_path_buf()))
            .expect_err("path-like pointer version must be rejected");

        assert!(format!("{err:#}").contains("must contain only"));
    }

    /// # Contract
    ///
    /// A persisted `trusted_key_id` is rendered by `rules status`;
    /// therefore pointer loading MUST reject terminal-control and
    /// delimiter characters before the text renderer sees them.
    #[test]
    fn current_install_rejects_unsafe_trusted_key_id() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install_root = tmp.path().join("rules");
        std::fs::create_dir_all(&install_root).unwrap();
        let pointer_path = install_root.join(CURRENT_POINTER_FILENAME);
        std::fs::write(
            &pointer_path,
            br#"{"version":"v0.1.0","trusted_key_id":"key\u001b[2J"}"#,
        )
        .unwrap();

        let err = current_install(Some(tmp.path().to_path_buf()))
            .expect_err("control characters in trusted_key_id must be rejected");

        assert!(format!("{err:#}").contains("trusted_key_id"));
    }
}
