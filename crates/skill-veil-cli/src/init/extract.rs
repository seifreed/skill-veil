//! Tarball extraction with hardened path-traversal and size protections.
//!
//! `tar` (the crate) supports arbitrary archive entries — symlinks,
//! hardlinks, absolute paths, `..`-laced relative paths. Any of those
//! could let a hostile or compromised release write outside the dest
//! dir. We reject every such entry up-front and only extract regular
//! files whose normalised path stays strictly inside `dest_dir`.

use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use tar::{Archive, EntryType};

/// Hard cap on the cumulative bytes extracted from a single tarball.
/// Mirrors [`super::download::MAX_TARBALL_BYTES`] times a small
/// expansion factor to allow for normal gzip ratios while blocking
/// zip-bomb-style amplification (a tiny tarball expanding to GBs of
/// disk).
const MAX_EXTRACTED_BYTES: u64 = 256 * 1024 * 1024;

/// Hard cap on the number of entries — guards against tarbombs that
/// shovel hundreds of thousands of zero-byte files to exhaust inodes.
const MAX_ENTRIES: usize = 5_000;

pub(crate) fn extract_into(tarball: &Path, dest_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dest_dir)
        .with_context(|| format!("creating extraction dir {}", dest_dir.display()))?;

    let canonical_dest = dest_dir
        .canonicalize()
        .with_context(|| format!("canonicalizing {}", dest_dir.display()))?;

    let file = std::fs::File::open(tarball)
        .with_context(|| format!("opening tarball {}", tarball.display()))?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);

    let mut total_bytes: u64 = 0;
    let mut entry_count: usize = 0;

    for entry in archive
        .entries()
        .with_context(|| format!("reading tarball entries from {}", tarball.display()))?
    {
        let mut entry = entry.context("reading tarball entry")?;

        entry_count += 1;
        if entry_count > MAX_ENTRIES {
            bail!(
                "tarball contains more than {MAX_ENTRIES} entries — refusing to extract \
                 (suspected tarbomb)"
            );
        }

        let header = entry.header().clone();
        let kind = header.entry_type();

        // GitHub's `archive/<sha>.tar.gz` puts a `pax_global_header`
        // entry at the start carrying repository-wide metadata. It
        // has no body to extract — we just skip it. Everything else
        // outside the regular-file / directory whitelist is rejected
        // up-front.
        if matches!(kind, EntryType::XGlobalHeader) {
            continue;
        }
        if !matches!(kind, EntryType::Regular | EntryType::Directory) {
            bail!(
                "tarball entry `{}` has disallowed type {:?} — refusing to extract",
                entry_path_for_error(&entry)?,
                kind
            );
        }

        let raw_path = entry
            .path()
            .with_context(|| "tarball entry path is not valid UTF-8")?
            .into_owned();
        let safe_rel = sanitize_relative_path(&raw_path)
            .with_context(|| format!("entry path `{}` is unsafe", raw_path.display()))?;

        let final_path = canonical_dest.join(&safe_rel);

        // Belt-and-suspenders: after joining, normalise and reject if
        // the resulting absolute path no longer starts with the
        // canonical dest. `sanitize_relative_path` already enforces
        // this, but layered defence is cheap and the cost of being
        // wrong is a write outside the user's cache.
        if !path_is_inside(&final_path, &canonical_dest) {
            bail!(
                "entry `{}` would resolve outside the extraction directory — refusing",
                raw_path.display()
            );
        }

        if matches!(kind, EntryType::Directory) {
            std::fs::create_dir_all(&final_path)
                .with_context(|| format!("creating dir {}", final_path.display()))?;
            continue;
        }

        let entry_size = header.size().context("entry size header missing")?;
        total_bytes = total_bytes
            .checked_add(entry_size)
            .ok_or_else(|| anyhow::anyhow!("cumulative size overflow"))?;
        if total_bytes > MAX_EXTRACTED_BYTES {
            bail!(
                "extracted bytes exceeded {MAX_EXTRACTED_BYTES} byte cap — refusing to continue \
                 (suspected zip-bomb-style amplification)"
            );
        }

        if let Some(parent) = final_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating parent dir {}", parent.display()))?;
        }
        let mut out = std::fs::File::create(&final_path)
            .with_context(|| format!("creating {}", final_path.display()))?;
        std::io::copy(&mut entry, &mut out)
            .with_context(|| format!("writing {}", final_path.display()))?;
    }

    Ok(())
}

fn entry_path_for_error<R: Read>(entry: &tar::Entry<R>) -> Result<String> {
    Ok(entry
        .path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<non-utf8>".to_string()))
}

/// Reject any path component that could escape the dest dir, or any
/// absolute / Windows-prefixed path that would bypass `Path::join`'s
/// "drop dest" semantics. Returns a clean relative `PathBuf` made of
/// only `Normal` components on success.
fn sanitize_relative_path(raw: &Path) -> Result<PathBuf> {
    let mut out = PathBuf::new();
    for comp in raw.components() {
        match comp {
            Component::Normal(part) => out.push(part),
            Component::CurDir => continue,
            Component::ParentDir => {
                bail!("tarball entry contains a `..` component");
            }
            Component::RootDir => {
                bail!("tarball entry is absolute (starts with `/`)");
            }
            Component::Prefix(_) => {
                bail!("tarball entry contains a Windows path prefix");
            }
        }
    }
    if out.as_os_str().is_empty() {
        bail!("tarball entry path resolves to empty after sanitisation");
    }
    Ok(out)
}

fn path_is_inside(child: &Path, parent: &Path) -> bool {
    let mut current = Some(child);
    while let Some(p) = current {
        if p == parent {
            return true;
        }
        current = p.parent();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tarball_with(entries: &[(&str, &[u8])]) -> tempfile::NamedTempFile {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use tar::{Builder, Header};
        let f = tempfile::NamedTempFile::new().unwrap();
        let gz = GzEncoder::new(f.reopen().unwrap(), Compression::default());
        let mut builder = Builder::new(gz);
        for (name, body) in entries {
            let mut hdr = Header::new_gnu();
            hdr.set_size(body.len() as u64);
            hdr.set_mode(0o644);
            hdr.set_cksum();
            builder.append_data(&mut hdr, name, *body).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap();
        f
    }

    /// Contract: a clean tarball with regular files extracts into the
    /// expected layout under dest.
    #[test]
    fn extracts_regular_files_into_dest() {
        let dest = TempDir::new().unwrap();
        let tar = tarball_with(&[
            ("official/core.yaml", b"a: 1\n"),
            ("official/behavioral.yaml", b"b: 2\n"),
        ]);
        extract_into(tar.path(), dest.path()).unwrap();
        assert_eq!(
            std::fs::read(dest.path().join("official/core.yaml")).unwrap(),
            b"a: 1\n"
        );
        assert_eq!(
            std::fs::read(dest.path().join("official/behavioral.yaml")).unwrap(),
            b"b: 2\n"
        );
    }

    /// Build a tarball with a single entry whose name we set by
    /// writing directly to the raw header bytes — bypasses
    /// `Header::set_path`'s validation, which is exactly what a
    /// hostile tarball-producer would do. `name` is treated as
    /// arbitrary bytes (NUL-terminated up to 100 bytes), so callers
    /// can inject `..` or absolute paths the safe API would refuse.
    fn tarball_with_raw_name(name: &[u8], body: &[u8]) -> tempfile::NamedTempFile {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use tar::{Builder, Header};
        let f = tempfile::NamedTempFile::new().unwrap();
        let gz = GzEncoder::new(f.reopen().unwrap(), Compression::default());
        let mut builder = Builder::new(gz);

        let mut hdr = Header::new_old();
        let old = hdr.as_old_mut();
        // Zero the name first so a residual `0x00` doesn't truncate
        // unexpectedly, then copy the malicious bytes verbatim.
        old.name = [0u8; 100];
        let n = name.len().min(old.name.len());
        old.name[..n].copy_from_slice(&name[..n]);
        hdr.set_size(body.len() as u64);
        hdr.set_mode(0o644);
        // `set_cksum` MUST be the last step before append: it hashes
        // the current header bytes and writes the result back into
        // the cksum field. Any later mutation invalidates it.
        hdr.set_cksum();

        builder.append(&hdr, body).unwrap();
        builder.into_inner().unwrap().finish().unwrap();
        f
    }

    /// Contract: a `..` component in a tarball entry is rejected
    /// outright. Pre-fix, `Path::join` would happily resolve outside
    /// `dest_dir` and `tar` would write there. This is the canonical
    /// path-traversal escape and the most important protection on the
    /// extraction path.
    #[test]
    fn rejects_dotdot_path_traversal() {
        let dest = TempDir::new().unwrap();
        let tar = tarball_with_raw_name(b"../escape.txt", b"pwn");
        let err = extract_into(tar.path(), dest.path()).expect_err("dotdot entry must be rejected");
        assert!(format!("{err:#}").contains(".."));
        let escape = dest.path().parent().unwrap().join("escape.txt");
        assert!(!escape.exists(), "no file should be written outside dest");
    }

    /// Contract: an absolute-path entry is rejected. The safe
    /// `Header::set_path` API blocks these by default; a hostile
    /// tarball producer can still craft one by writing the name
    /// bytes directly. We MUST reject at the extractor boundary.
    #[test]
    fn rejects_absolute_path_entry() {
        let dest = TempDir::new().unwrap();
        let tar = tarball_with_raw_name(b"/etc/passwd", b"root::0:0::/root:/bin/sh");
        let err =
            extract_into(tar.path(), dest.path()).expect_err("absolute entry must be rejected");
        let msg = format!("{err:#}").to_ascii_lowercase();
        assert!(
            msg.contains("absolute") || msg.contains("..") || msg.contains("unsafe"),
            "error must explain why the entry was rejected: {msg}"
        );
    }

    /// Contract: a symlink entry is rejected even if the target looks
    /// innocuous. Once a symlink lands in the cache, a later write
    /// through it could escape. We do not extract symlinks at all.
    #[test]
    fn rejects_symlink_entries() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use tar::{Builder, EntryType, Header};
        let f = tempfile::NamedTempFile::new().unwrap();
        let gz = GzEncoder::new(f.reopen().unwrap(), Compression::default());
        let mut builder = Builder::new(gz);
        let mut hdr = Header::new_gnu();
        hdr.set_size(0);
        hdr.set_mode(0o777);
        hdr.set_entry_type(EntryType::Symlink);
        hdr.set_link_name("/etc/passwd").unwrap();
        hdr.set_cksum();
        builder
            .append_data(&mut hdr, "passwd_link", &b""[..])
            .unwrap();
        builder.into_inner().unwrap().finish().unwrap();

        let dest = TempDir::new().unwrap();
        let err = extract_into(f.path(), dest.path()).expect_err("symlink entry must be rejected");
        assert!(format!("{err:#}").contains("disallowed type"));
    }

    /// Contract: more than `MAX_ENTRIES` entries trips the tarbomb
    /// guard. Use a small synthetic count above the threshold to keep
    /// the test fast.
    #[test]
    fn rejects_excessive_entry_count() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use tar::{Builder, Header};
        let f = tempfile::NamedTempFile::new().unwrap();
        let gz = GzEncoder::new(f.reopen().unwrap(), Compression::default());
        let mut builder = Builder::new(gz);
        for i in 0..(MAX_ENTRIES + 1) {
            let mut hdr = Header::new_gnu();
            hdr.set_size(0);
            hdr.set_mode(0o644);
            hdr.set_cksum();
            builder
                .append_data(&mut hdr, format!("f{i}.txt"), &b""[..])
                .unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap();

        let dest = TempDir::new().unwrap();
        let err = extract_into(f.path(), dest.path()).expect_err("> MAX_ENTRIES must be rejected");
        assert!(format!("{err:#}").contains("tarbomb"));
    }
}
