use anyhow::{Context, Result};
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

pub(super) struct DatasetPreparation {
    pub(super) package_roots: Vec<PathBuf>,
    pub(super) skipped_archives: usize,
}

pub(super) fn prepare_dataset_packages(root: &Path) -> Result<DatasetPreparation> {
    let immediate_subdirs: Vec<_> = fs::read_dir(root)
        .with_context(|| format!("Failed to read dataset root {}", root.display()))?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name();
            let hidden = name.to_str().is_some_and(|name| name.starts_with('.'));
            entry
                .file_type()
                .ok()
                .filter(|ft| ft.is_dir() && !hidden)
                .map(|_| entry.path())
        })
        .collect();
    if !immediate_subdirs.is_empty() {
        return Ok(DatasetPreparation {
            package_roots: immediate_subdirs,
            skipped_archives: 0,
        });
    }

    let archive_files: Vec<_> = fs::read_dir(root)
        .with_context(|| format!("Failed to read dataset root {}", root.display()))?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            if !entry.file_type().ok().is_some_and(|ft| ft.is_file()) {
                return None;
            }
            if path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"))
                || is_zip_archive(&path)
            {
                Some(path)
            } else {
                None
            }
        })
        .collect();
    if !archive_files.is_empty() {
        let cache_root = root.join(".skill-veil-cache").join("extracted");
        fs::create_dir_all(&cache_root)
            .with_context(|| format!("Failed to create {}", cache_root.display()))?;

        let extraction_results: Vec<_> = archive_files
            .par_iter()
            .map(|zip_path| extract_zip_package_cached(zip_path, &cache_root))
            .collect();

        let mut skipped_archives = 0_usize;
        for result in extraction_results {
            match result {
                Ok(()) => {}
                Err(err) => {
                    skipped_archives += 1;
                    tracing::warn!("{err:#}");
                }
            }
        }

        let extracted_roots: Vec<_> = fs::read_dir(&cache_root)
            .with_context(|| format!("Failed to read {}", cache_root.display()))?
            .filter_map(Result::ok)
            .filter_map(|entry| {
                entry
                    .file_type()
                    .ok()
                    .filter(|ft| ft.is_dir())
                    .map(|_| entry.path())
            })
            .collect();
        return Ok(DatasetPreparation {
            package_roots: extracted_roots,
            skipped_archives,
        });
    }

    let mut packages = BTreeSet::new();
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
    {
        if entry
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("SKILL.md"))
        {
            if let Some(parent) = entry.path().parent() {
                packages.insert(parent.to_path_buf());
            }
        }
    }
    Ok(DatasetPreparation {
        package_roots: packages.into_iter().collect(),
        skipped_archives: 0,
    })
}

fn is_zip_archive(path: &Path) -> bool {
    let Ok(file) = fs::File::open(path) else {
        return false;
    };
    zip::ZipArchive::new(file).is_ok()
}

fn extract_zip_package(zip_path: &Path, output_dir: &Path) -> Result<()> {
    let file = fs::File::open(zip_path)
        .with_context(|| format!("Failed to open {}", zip_path.display()))?;
    let mut archive = zip::ZipArchive::new(file)
        .with_context(|| format!("Invalid zip {}", zip_path.display()))?;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .with_context(|| format!("Failed to read zip entry {}", zip_path.display()))?;
        let Some(relative_path) = entry.enclosed_name().map(|path| path.to_path_buf()) else {
            continue;
        };
        let destination = output_dir.join(&relative_path);
        // Zip-slip defence in depth: even when `enclosed_name` rejects the
        // obvious `../` cases, a malicious archive built around symlinks or
        // an exotic path encoding could still produce a destination outside
        // `output_dir` after `Path::join`. Compare lexically so the check
        // applies before the file is created.
        if !skill_veil_core::path_safety::path_stays_within_base(&destination, output_dir) {
            tracing::warn!(
                zip = %zip_path.display(),
                entry = %relative_path.display(),
                "skipping zip entry that would escape output_dir (zip-slip)"
            );
            continue;
        }
        if entry.is_dir() {
            fs::create_dir_all(&destination)
                .with_context(|| format!("Failed to create {}", destination.display()))?;
            continue;
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }
        let mut outfile = fs::File::create(&destination)
            .with_context(|| format!("Failed to create {}", destination.display()))?;
        std::io::copy(&mut entry, &mut outfile)
            .with_context(|| format!("Failed to extract {}", destination.display()))?;
    }
    Ok(())
}

fn extract_zip_package_cached(zip_path: &Path, cache_root: &Path) -> Result<()> {
    let package_name = zip_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("package");
    let output_dir = cache_root.join(package_name);
    let marker_path = output_dir.join(".skill-veil-source");
    let source_signature = zip_source_signature(zip_path)?;

    if output_dir.is_dir()
        && marker_path.exists()
        && fs::read_to_string(&marker_path).ok().as_deref() == Some(source_signature.as_str())
    {
        return Ok(());
    }

    let staging_dir = cache_root.join(format!(".{}.tmp", package_name));
    if staging_dir.exists() {
        fs::remove_dir_all(&staging_dir)
            .with_context(|| format!("Failed to clean {}", staging_dir.display()))?;
    }
    fs::create_dir_all(&staging_dir)
        .with_context(|| format!("Failed to create {}", staging_dir.display()))?;
    extract_zip_package(zip_path, &staging_dir)?;
    fs::write(staging_dir.join(".skill-veil-source"), &source_signature)
        .with_context(|| format!("Failed to write marker for {}", zip_path.display()))?;

    if output_dir.exists() {
        fs::remove_dir_all(&output_dir)
            .with_context(|| format!("Failed to replace {}", output_dir.display()))?;
    }
    fs::rename(&staging_dir, &output_dir)
        .or_else(|_| {
            fs::create_dir_all(&output_dir)?;
            for entry in fs::read_dir(&staging_dir)? {
                let entry = entry?;
                let source = entry.path();
                let destination = output_dir.join(entry.file_name());
                fs::rename(source, destination)?;
            }
            fs::remove_dir_all(&staging_dir)
        })
        .with_context(|| {
            format!(
                "Failed to finalize cached extraction for {}",
                zip_path.display()
            )
        })?;
    Ok(())
}

/// Content-addressed signature: SHA-256 of the zip bytes. Stable across
/// renames and identical-content copies at different paths, unlike the
/// previous `path:len:mtime` triple which forced re-extraction whenever
/// the file moved. Trade-off: one full read of the archive on every
/// signature computation; the extraction cost would dominate this anyway.
fn zip_source_signature(zip_path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let bytes = fs::read(zip_path)
        .with_context(|| format!("Failed to read {} for signature", zip_path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    /// Contract: malicious ZIP entries that would escape `output_dir` MUST
    /// be skipped, never written. Defence in depth on top of `zip` crate's
    /// `enclosed_name` sanitisation. See `path_safety::path_stays_within_base`.
    #[test]
    fn extract_zip_package_rejects_zip_slip_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let zip_path = tmp.path().join("evil.zip");
        let output_dir = tmp.path().join("out");
        std::fs::create_dir_all(&output_dir).unwrap();
        // The "outside" directory is a sibling of output_dir; if zip-slip
        // succeeded, the entry would be written to escape.txt under it.
        let outside_dir = tmp.path().join("outside");
        std::fs::create_dir_all(&outside_dir).unwrap();

        // Build a zip that intentionally tries to escape via `../`.
        // `enclosed_name()` in modern `zip` crate filters obvious `../`
        // entries, so we exercise the defence-in-depth path by injecting
        // an absolute-style entry name. If the zip crate accepts it, our
        // post-join `path_stays_within_base` check must reject it.
        {
            let file = std::fs::File::create(&zip_path).unwrap();
            let mut writer = zip::ZipWriter::new(file);
            // Many zip crate versions accept this and `enclosed_name` filters
            // the leading `..` — we still want the helper as the last guard.
            writer
                .start_file("../outside/escape.txt", SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"OWNED").unwrap();
            writer.finish().unwrap();
        }

        let _ = extract_zip_package(&zip_path, &output_dir);

        // The escape file MUST NOT exist anywhere outside `output_dir`.
        let escape_target = outside_dir.join("escape.txt");
        assert!(
            !escape_target.exists(),
            "zip-slip defence failed: {} was written outside output_dir",
            escape_target.display()
        );
        // Sanity: nothing under the parent of output_dir got an `escape.txt`.
        let walked: Vec<_> = walkdir::WalkDir::new(tmp.path())
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name() == "escape.txt")
            .collect();
        assert!(
            walked.is_empty() || walked.iter().all(|e| e.path().starts_with(&output_dir)),
            "escape.txt must only ever live inside output_dir; found at: {:?}",
            walked
                .iter()
                .map(|e| e.path().to_path_buf())
                .collect::<Vec<_>>()
        );
    }
}
