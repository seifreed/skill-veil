//! Cryptographic verification of a downloaded rules-pack release.
//!
//! Two independent checks must both pass before any extracted rule
//! becomes visible to the scanner:
//!
//! 1. **Manifest signature.** The detached Ed25519 signature in
//!    `manifest.json.sig` must verify against [`crate::init::keys`]'s
//!    embedded public keys, treating `manifest.json` as the message
//!    (PureEd25519 / RFC 8032).
//! 2. **Per-file SHA-256.** Every file listed in the manifest must
//!    exist in the extracted tree with a SHA-256 digest equal to the
//!    manifest entry. Any mismatch — or any file present on disk that
//!    is NOT in the manifest — fails the verification.
//!
//! Both checks are intentionally redundant: a bad signature already
//! implies the manifest cannot be trusted, but per-file hashing also
//! catches bugs in the extract path (path traversal, partial writes)
//! that signature verification alone would miss.

use super::manifest::Manifest;
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Signature, Verifier};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{File, Metadata};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

const MAX_MANIFEST_ENTRY_BYTES: u64 = 64 * 1024 * 1024;

/// Verify a base64-encoded detached Ed25519 signature over the raw
/// `manifest.json` bytes against the embedded trusted keys. Returns
/// the id of the key that accepted the signature on success.
///
/// # Why we strip ASCII whitespace
/// `scripts/sign-manifest.sh` writes the signature with a trailing
/// newline so the file ends cleanly when viewed with `cat`. Stripping
/// whitespace lets us accept either `cat`-friendly or strict-base64
/// inputs without operator confusion.
pub(crate) fn verify_manifest_signature(
    manifest_bytes: &[u8],
    signature_b64_with_whitespace: &[u8],
) -> Result<&'static str> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let cleaned: Vec<u8> = signature_b64_with_whitespace
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let sig_bytes = STANDARD
        .decode(&cleaned)
        .context("manifest.json.sig is not valid base64")?;
    let signature = Signature::from_slice(&sig_bytes)
        .context("manifest.json.sig is not a 64-byte Ed25519 signature")?;

    let trusted = super::keys::verifying_keys()
        .map_err(|e| anyhow!("embedded trusted keys are corrupt: {e}"))?;

    for (id, vk) in &trusted {
        if vk.verify(manifest_bytes, &signature).is_ok() {
            tracing::info!(
                key_id = %id,
                "manifest signature verified against trusted key"
            );
            return Ok(*id);
        }
    }

    bail!(
        "manifest.json.sig did not verify against any of the {} embedded trusted keys — \
         either the release was not signed by a current maintainer key, or the manifest \
         was tampered with after signing",
        trusted.len(),
    )
}

/// Verify every file listed in the manifest against its on-disk
/// SHA-256, AND verify the on-disk tree contains exactly the files the
/// manifest declares — no extras, no missing entries.
///
/// `extracted_root` is the directory the tarball was extracted into.
pub(crate) fn verify_manifest_against_extracted(
    manifest: &Manifest,
    extracted_root: &Path,
) -> Result<()> {
    verify_manifest_against_extracted_with_cap(manifest, extracted_root, MAX_MANIFEST_ENTRY_BYTES)
}

fn verify_manifest_against_extracted_with_cap(
    manifest: &Manifest,
    extracted_root: &Path,
    max_entry_bytes: u64,
) -> Result<()> {
    let mut declared: BTreeSet<String> = BTreeSet::new();

    for entry in &manifest.files {
        if !declared.insert(entry.path.clone()) {
            bail!(
                "manifest declares duplicate path `{}` - refusing ambiguous release manifest",
                entry.path
            );
        }
        let path = manifest_entry_path(extracted_root, &entry.path)?;
        let (actual_size, actual) = hash_manifest_file_with_cap(&path, max_entry_bytes)
            .with_context(|| {
                format!(
                    "manifest declares `{}` but it is missing from the extracted tarball",
                    entry.path
                )
            })?;

        if let Some(expected_size) = entry.size_bytes {
            if expected_size > max_entry_bytes {
                bail!(
                    "size mismatch for `{}`: manifest says {} bytes, exceeding per-file cap {}",
                    entry.path,
                    expected_size,
                    max_entry_bytes
                );
            }
            if actual_size != expected_size {
                bail!(
                    "size mismatch for `{}`: manifest says {} bytes, on-disk has {}",
                    entry.path,
                    expected_size,
                    actual_size
                );
            }
        }

        if !actual.eq_ignore_ascii_case(&entry.sha256) {
            bail!(
                "SHA-256 mismatch for `{}`: manifest declares `{}`, computed `{}`",
                entry.path,
                entry.sha256,
                actual
            );
        }
    }

    // Reject extracted files NOT covered by the manifest. A signed
    // manifest with a tarball containing extra unsigned content would
    // let an attacker smuggle rules past the integrity check.
    let mut on_disk: BTreeSet<String> = BTreeSet::new();
    walk_collect(extracted_root, extracted_root, &mut on_disk)?;

    let manifest_meta_files: BTreeSet<String> = ["manifest.json", "manifest.json.sig"]
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    for entry in &on_disk {
        if manifest_meta_files.contains(entry) {
            continue;
        }
        if !declared.contains(entry) {
            bail!(
                "extracted tarball contains `{}` which is NOT listed in the signed manifest — \
                 refusing to load potentially smuggled content",
                entry
            );
        }
    }

    Ok(())
}

fn hash_manifest_file_with_cap(path: &Path, cap: u64) -> Result<(u64, String)> {
    let path_meta = regular_manifest_file_metadata(path)?;
    let file = File::open(path)?;
    let opened_meta = file
        .metadata()
        .with_context(|| format!("stat opened manifest file {}", path.display()))?;
    if !opened_file_matches_path(&opened_meta, &path_meta) {
        bail!(
            "refusing to hash {}: path changed while opening",
            path.display()
        );
    }
    if opened_meta.len() > cap {
        bail!(
            "refusing to hash {}: file exceeds per-file cap {}",
            path.display(),
            cap
        );
    }
    let mut reader = std::io::BufReader::new(file).take(cap.saturating_add(1));
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total_read = 0_u64;

    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        total_read = total_read
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("manifest file byte count overflow"))?;
        if total_read > cap {
            bail!(
                "refusing to hash {}: file exceeds per-file cap {}",
                path.display(),
                cap
            );
        }
        hasher.update(&buf[..read]);
    }
    debug_assert!(
        total_read <= cap,
        "manifest file reader must reject streams over the cap"
    );

    Ok((total_read, hex::encode(hasher.finalize())))
}

fn regular_manifest_file_metadata(path: &Path) -> Result<Metadata> {
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("stat manifest file {}", path.display()))?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        bail!("refusing to hash {}: not a regular file", path.display())
    }
    if !has_single_hardlink(&meta) {
        bail!(
            "refusing to hash {}: file has multiple hard links",
            path.display()
        )
    }
    Ok(meta)
}

fn manifest_entry_path(extracted_root: &Path, raw: &str) -> Result<PathBuf> {
    if raw.contains('\\') {
        bail!("manifest path `{raw}` contains a backslash separator");
    }

    let mut rel = PathBuf::new();
    for comp in Path::new(raw).components() {
        match comp {
            Component::Normal(part) => rel.push(part),
            Component::CurDir => continue,
            Component::ParentDir => bail!("manifest path `{raw}` contains a `..` component"),
            Component::RootDir => bail!("manifest path `{raw}` is absolute"),
            Component::Prefix(_) => bail!("manifest path `{raw}` contains a Windows path prefix"),
        }
    }
    if rel.as_os_str().is_empty() {
        bail!("manifest path `{raw}` resolves to empty after sanitisation");
    }

    let path = extracted_root.join(rel);
    debug_assert!(
        path.starts_with(extracted_root),
        "manifest entry path must stay under extracted root"
    );
    Ok(path)
}

fn walk_collect(root: &Path, dir: &Path, out: &mut BTreeSet<String>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            walk_collect(root, &path, out)?;
        } else if file_type.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|e| anyhow!("strip_prefix failed for {}: {e}", path.display()))?;
            // Use forward-slash form to match the manifest, which is
            // generated by a POSIX shell and uses unix paths verbatim.
            out.insert(rel.to_string_lossy().replace('\\', "/"));
        } else {
            let rel = path
                .strip_prefix(root)
                .map_err(|e| anyhow!("strip_prefix failed for {}: {e}", path.display()))?;
            bail!(
                "extracted tarball contains non-regular entry `{}` — refusing to load",
                rel.to_string_lossy().replace('\\', "/")
            );
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write(root: &Path, rel: &str, body: &[u8]) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    fn sha256_hex(body: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(body);
        hex::encode(h.finalize())
    }

    fn make_manifest(files: &[(&str, &[u8])]) -> Manifest {
        Manifest {
            schema_version: super::super::manifest::SUPPORTED_SCHEMA_VERSION.to_string(),
            version: "v-test".to_string(),
            files: files
                .iter()
                .map(|(path, body)| super::super::manifest::ManifestEntry {
                    path: (*path).to_string(),
                    sha256: sha256_hex(body),
                    size_bytes: Some(body.len() as u64),
                })
                .collect(),
        }
    }

    /// Contract: a clean extracted tarball passes both checks.
    #[test]
    fn happy_path_passes_full_verification() {
        let dir = TempDir::new().unwrap();
        let body = b"rule: do_thing\n";
        write(dir.path(), "official/core.yaml", body);
        let manifest = make_manifest(&[("official/core.yaml", body)]);
        verify_manifest_against_extracted(&manifest, dir.path())
            .expect("clean extraction must verify");
    }

    /// # Contract
    ///
    /// A release manifest may name each extracted file at most once.
    /// Duplicate path entries are ambiguous audit evidence even when
    /// both entries carry the same hash.
    #[test]
    fn duplicate_manifest_paths_are_rejected() {
        let dir = TempDir::new().unwrap();
        let body = b"rule: do_thing\n";
        write(dir.path(), "official/core.yaml", body);
        let manifest = make_manifest(&[("official/core.yaml", body), ("official/core.yaml", body)]);

        let err = verify_manifest_against_extracted(&manifest, dir.path())
            .expect_err("duplicate manifest path must be rejected");

        assert!(format!("{err:#}").contains("duplicate path"));
    }

    /// Contract: manifest paths name files inside the extracted tree.
    /// Parent components are invalid even when a same-hash file exists
    /// outside the tree.
    #[test]
    fn manifest_parent_paths_are_rejected_before_file_read() {
        let dir = TempDir::new().unwrap();
        let body = b"rule: do_thing\n";
        let outside =
            tempfile::NamedTempFile::new_in(dir.path().parent().unwrap()).expect("outside file");
        fs::write(outside.path(), body).expect("write outside file");
        let outside_name = outside.path().file_name().unwrap().to_string_lossy();
        let manifest_path = format!("../{outside_name}");
        let manifest = make_manifest(&[(&manifest_path, body)]);

        let err = verify_manifest_against_extracted(&manifest, dir.path())
            .expect_err("manifest parent path must be rejected");

        assert!(format!("{err:#}").contains(".."));
    }

    /// Contract: manifest paths are relative POSIX paths. Absolute
    /// filesystem paths must not be interpreted as extracted files.
    #[test]
    fn manifest_absolute_paths_are_rejected_before_file_read() {
        let dir = TempDir::new().unwrap();
        let body = b"rule: do_thing\n";
        let outside = tempfile::NamedTempFile::new().expect("outside file");
        fs::write(outside.path(), body).expect("write outside file");
        let manifest_path = outside.path().to_string_lossy().to_string();
        let manifest = make_manifest(&[(&manifest_path, body)]);

        let err = verify_manifest_against_extracted(&manifest, dir.path())
            .expect_err("manifest absolute path must be rejected");
        let msg = format!("{err:#}");

        assert!(
            msg.contains("absolute") || msg.contains("Windows path prefix"),
            "unexpected error: {msg}"
        );
    }

    /// Contract: any byte tampering in an extracted file fails the
    /// per-file SHA-256 check, even if the manifest itself is signed.
    /// This is the redundancy the doc-comment promises.
    #[test]
    fn tampered_extracted_file_fails_sha256() {
        let dir = TempDir::new().unwrap();
        let body = b"rule: do_thing\n";
        write(dir.path(), "official/core.yaml", body);
        let manifest = make_manifest(&[("official/core.yaml", body)]);

        // Mutate ONE byte after manifest is built.
        write(dir.path(), "official/core.yaml", b"rule: do_evil!\n");

        let err = verify_manifest_against_extracted(&manifest, dir.path())
            .expect_err("tampered file must fail");
        assert!(format!("{err}").contains("SHA-256 mismatch"));
    }

    /// # Contract
    ///
    /// Per-file manifest verification is streaming and MUST accept an
    /// extracted file whose size is exactly the configured cap.
    #[test]
    fn manifest_entry_at_per_file_cap_passes_verification() {
        let dir = TempDir::new().unwrap();
        let body = b"12345678";
        write(dir.path(), "official/core.yaml", body);
        let manifest = make_manifest(&[("official/core.yaml", body)]);

        let cap = u64::try_from(body.len()).unwrap();
        verify_manifest_against_extracted_with_cap(&manifest, dir.path(), cap)
            .expect("file exactly at cap must verify");
    }

    /// # Contract
    ///
    /// Per-file manifest verification MUST reject an entry larger than
    /// the configured cap before allocating the full file body.
    #[test]
    fn manifest_entry_over_per_file_cap_is_rejected() {
        let dir = TempDir::new().unwrap();
        let body = b"123456789";
        write(dir.path(), "official/core.yaml", body);
        let manifest = make_manifest(&[("official/core.yaml", body)]);

        let err = verify_manifest_against_extracted_with_cap(&manifest, dir.path(), 8)
            .expect_err("entry over cap must fail");

        assert!(format!("{err:#}").contains("per-file cap"));
    }

    /// # Contract
    ///
    /// Manifest verification only hashes regular files. A symlinked
    /// manifest entry is rejected instead of hashing the target.
    #[cfg(unix)]
    #[test]
    fn manifest_entry_symlink_is_rejected() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target.yaml");
        let link = dir.path().join("official").join("core.yaml");
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::fs::write(&target, b"rule: do_thing\n").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let manifest = make_manifest(&[("official/core.yaml", b"rule: do_thing\n")]);

        let err = verify_manifest_against_extracted(&manifest, dir.path())
            .expect_err("symlink manifest entry must fail");

        assert!(format!("{err:#}").contains("not a regular file"));
    }

    /// # Contract
    ///
    /// Manifest verification only hashes files owned by the extracted
    /// tree. A hardlinked manifest entry is rejected instead of trusting
    /// an inode that also has a directory entry outside the install root.
    #[cfg(unix)]
    #[test]
    fn manifest_entry_hardlink_is_rejected() {
        let dir = TempDir::new().unwrap();
        let extracted = dir.path().join("extracted");
        std::fs::create_dir(&extracted).unwrap();
        let target = dir.path().join("target.yaml");
        let link = extracted.join("official").join("core.yaml");
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::fs::write(&target, b"rule: do_thing\n").unwrap();
        std::fs::hard_link(&target, &link).unwrap();
        let manifest = make_manifest(&[("official/core.yaml", b"rule: do_thing\n")]);

        let err = verify_manifest_against_extracted(&manifest, &extracted)
            .expect_err("hardlinked manifest entry must fail");

        assert!(format!("{err:#}").contains("multiple hard links"));
    }

    /// Contract: an extra file in the extracted tarball that is NOT in
    /// the signed manifest is rejected. This blocks the smuggling
    /// attack: an attacker could otherwise sign a small manifest but
    /// stuff a large tarball with malicious extras.
    #[test]
    fn extra_file_outside_manifest_is_rejected() {
        let dir = TempDir::new().unwrap();
        let body = b"rule: do_thing\n";
        write(dir.path(), "official/core.yaml", body);
        write(dir.path(), "official/SMUGGLED.yaml", b"rule: !!!\n");
        let manifest = make_manifest(&[("official/core.yaml", body)]);
        let err = verify_manifest_against_extracted(&manifest, dir.path())
            .expect_err("extra file must be rejected");
        assert!(format!("{err}").contains("SMUGGLED.yaml"));
    }

    /// # Contract
    ///
    /// Any non-regular extra entry in the extracted tree is rejected,
    /// even when it is not listed in the manifest.
    #[cfg(unix)]
    #[test]
    fn extra_symlink_outside_manifest_is_rejected() {
        let dir = TempDir::new().unwrap();
        let body = b"rule: do_thing\n";
        write(dir.path(), "official/core.yaml", body);
        let target = dir.path().join("target.yaml");
        let link = dir.path().join("official").join("linked.yaml");
        std::fs::write(&target, b"linked").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let manifest = make_manifest(&[("official/core.yaml", body)]);

        let err = verify_manifest_against_extracted(&manifest, dir.path())
            .expect_err("extra symlink must fail verification");

        assert!(format!("{err:#}").contains("non-regular entry"));
    }

    /// Contract: a missing file in the extracted tarball whose entry
    /// is in the manifest fails verification with a path-anchored
    /// error so the operator can grep the message.
    #[test]
    fn missing_extracted_file_fails_with_path_in_error() {
        let dir = TempDir::new().unwrap();
        let manifest = make_manifest(&[("official/core.yaml", b"x")]);
        let err = verify_manifest_against_extracted(&manifest, dir.path())
            .expect_err("missing file must fail");
        assert!(format!("{err}").contains("official/core.yaml"));
    }

    /// Contract: a syntactically valid but semantically wrong
    /// signature (here all-zeros) is rejected by every embedded
    /// trusted key, surfacing the "did not verify" error path. We
    /// avoid generating a real keypair to keep `rand_core` out of the
    /// dependency graph — the rejection path is what matters here.
    #[test]
    fn all_zero_signature_is_rejected_by_every_trusted_key() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let zero_sig: [u8; 64] = [0u8; 64];
        let sig_b64 = format!("{}\n", STANDARD.encode(zero_sig));
        let err = verify_manifest_signature(b"any message", sig_b64.as_bytes())
            .expect_err("all-zeros signature must not verify");
        assert!(format!("{err}").contains("did not verify"));
    }

    /// Contract: a non-base64 signature surfaces a base64 parse error,
    /// not a panic. The error message names the field so an operator
    /// who corrupted the file knows what to fix.
    #[test]
    fn invalid_base64_in_signature_returns_named_error() {
        let err = verify_manifest_signature(b"manifest", b"!!!not-base64!!!")
            .expect_err("invalid base64 must error");
        assert!(format!("{err:#}").contains("manifest.json.sig"));
    }

    /// Contract: a base64-decoded signature whose length is not 64
    /// bytes is rejected at the Signature::from_slice boundary with
    /// an error that names the manifest signature field. Pre-fix this
    /// would have panicked in `Signature::from_bytes` (fixed-size
    /// constructor); using `from_slice` returns a Result instead.
    #[test]
    fn wrong_length_signature_returns_named_error() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let too_short = STANDARD.encode([0u8; 32]); // only 32 bytes
        let err = verify_manifest_signature(b"manifest", too_short.as_bytes())
            .expect_err("32-byte sig must be rejected");
        assert!(format!("{err:#}").contains("64-byte"));
    }
}
