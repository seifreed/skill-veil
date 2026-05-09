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
use std::path::Path;

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
    let mut declared: BTreeSet<String> = BTreeSet::new();

    for entry in &manifest.files {
        declared.insert(entry.path.clone());
        let path = extracted_root.join(&entry.path);
        let bytes = std::fs::read(&path).with_context(|| {
            format!(
                "manifest declares `{}` but it is missing from the extracted tarball",
                entry.path
            )
        })?;

        if let Some(expected_size) = entry.size_bytes {
            if bytes.len() as u64 != expected_size {
                bail!(
                    "size mismatch for `{}`: manifest says {} bytes, on-disk has {}",
                    entry.path,
                    expected_size,
                    bytes.len()
                );
            }
        }

        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let actual = hex::encode(hasher.finalize());
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
        }
    }
    Ok(())
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
