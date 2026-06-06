//! One-shot SHA-256 hex digest, shared by the disk caches and VT enrichment
//! so the `Sha256::new(); update(..); format!("{:x}", finalize())` idiom is
//! not re-inlined under a different name per call site.

use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

/// Lowercase hex SHA-256 of `bytes`.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Lowercase hex SHA-256 of a regular file's contents, streamed with a byte
/// cap. Reads one byte past `cap` so a file that grows past the cap between a
/// stat and this read cannot drive an unbounded allocation. Returns `Ok(None)`
/// when `path` is not a regular file, is a symlink, or exceeds `cap`.
pub(crate) fn sha256_file_with_cap(path: &Path, cap: u64) -> std::io::Result<Option<String>> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Ok(None);
    }
    let file = std::fs::File::open(path)?;
    let mut reader = file.take(cap.saturating_add(1));
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > cap {
            return Ok(None);
        }
        hasher.update(&buf[..read]);
    }
    Ok(Some(format!("{:x}", hasher.finalize())))
}

/// First seven characters of a SHA / commit hash for display, never
/// splitting a UTF-8 codepoint. Shared by the rule-update notifier and the
/// init / NOVA status output so the "short SHA" form has one definition.
pub(crate) fn short_sha(sha: &str) -> &str {
    let end = sha.char_indices().nth(7).map_or(sha.len(), |(idx, _)| idx);
    &sha[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: takes the first seven characters and never slices across a
    /// UTF-8 boundary (commit SHAs are ASCII, but the helper must stay
    /// panic-free on arbitrary input).
    #[test]
    fn short_sha_takes_seven_chars_utf8_safe() {
        assert_eq!(short_sha("abcdefghi"), "abcdefg");
        assert_eq!(short_sha("åååååååå"), "ååååååå");
        assert_eq!(short_sha("abc"), "abc");
    }

    #[test]
    fn sha256_hex_matches_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// Contract: a file at or under the cap hashes to the same digest as the
    /// one-shot helper over its bytes.
    #[test]
    fn sha256_file_with_cap_hashes_file_under_cap() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("f.bin");
        std::fs::write(&path, b"abc").unwrap();

        let digest = sha256_file_with_cap(&path, 1024).unwrap();

        assert_eq!(digest.as_deref(), Some(sha256_hex(b"abc").as_str()));
    }

    /// Contract: a file larger than the cap yields `None` instead of reading
    /// the whole (potentially unbounded) file into memory.
    #[test]
    fn sha256_file_with_cap_rejects_file_over_cap() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("big.bin");
        std::fs::write(&path, vec![b'x'; 4096]).unwrap();

        assert_eq!(sha256_file_with_cap(&path, 8).unwrap(), None);
    }
}
