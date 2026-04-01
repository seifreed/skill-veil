use crate::domain_types::{
    LockfileCoverageSummary, LockfileInventoryEntry, ManifestInventoryEntry, PackageIdentity,
    PackageIdentityLineage, PackageLineageDrift,
};
use std::collections::BTreeSet;

pub(super) fn derive_lockfile_coverage(
    manifests: &[ManifestInventoryEntry],
    lockfiles: &[LockfileInventoryEntry],
) -> LockfileCoverageSummary {
    let present_lockfiles: BTreeSet<_> = lockfiles
        .iter()
        .filter_map(|entry| {
            std::path::Path::new(&entry.path)
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.to_ascii_lowercase())
        })
        .collect();
    let mut manifests_with_expected_lockfiles = 0_usize;
    let mut manifests_with_present_lockfiles = 0_usize;
    let mut missing_expected_lockfiles = Vec::new();

    for manifest in manifests {
        if manifest.expected_lockfiles.is_empty() {
            continue;
        }
        manifests_with_expected_lockfiles += 1;
        let has_present_lockfile = manifest
            .expected_lockfiles
            .iter()
            .any(|expected| present_lockfiles.contains(&expected.to_ascii_lowercase()));
        if has_present_lockfile {
            manifests_with_present_lockfiles += 1;
        } else {
            missing_expected_lockfiles.push(format!(
                "{} -> {}",
                manifest.path,
                manifest.expected_lockfiles.join(" | ")
            ));
        }
    }

    LockfileCoverageSummary {
        manifests_with_expected_lockfiles,
        manifests_with_present_lockfiles,
        missing_expected_lockfiles,
    }
}

pub(super) fn derive_lineage_notes(
    manifests: &[ManifestInventoryEntry],
    lockfiles: &[LockfileInventoryEntry],
    package_identities: &[PackageIdentity],
    package_lineage: &[PackageIdentityLineage],
) -> Vec<String> {
    let manifest_ecosystems = manifests
        .iter()
        .map(|entry| entry.ecosystem.clone())
        .collect::<BTreeSet<_>>();
    let lockfile_ecosystems = lockfiles
        .iter()
        .map(|entry| entry.ecosystem.clone())
        .collect::<BTreeSet<_>>();
    let mut notes = Vec::new();

    if manifest_ecosystems.len() > 1 {
        notes.push(format!(
            "multiple ecosystems/toolchains observed: {}",
            manifest_ecosystems
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    for ecosystem in lockfile_ecosystems.difference(&manifest_ecosystems) {
        notes.push(format!(
            "lockfile ecosystem has no matching manifest: {ecosystem}"
        ));
    }

    for manifest in manifests {
        let Some(manager) = manifest.declared_package_manager.as_deref() else {
            continue;
        };
        let expected_lockfile_kind = match manager {
            "pnpm" => Some("pnpm_lock"),
            "yarn" => Some("yarn_lock"),
            "npm" => Some("package_lock"),
            _ => None,
        };
        let Some(expected_lockfile_kind) = expected_lockfile_kind else {
            continue;
        };
        let package_dir = std::path::Path::new(&manifest.path)
            .parent()
            .map(|path| path.to_path_buf());
        let sibling_lockfiles = lockfiles
            .iter()
            .filter(|entry| {
                std::path::Path::new(&entry.path)
                    .parent()
                    .map(|path| path.to_path_buf())
                    == package_dir
            })
            .collect::<Vec<_>>();
        if sibling_lockfiles.is_empty() {
            continue;
        }
        let has_expected_lockfile = sibling_lockfiles
            .iter()
            .any(|entry| entry.lockfile_kind == expected_lockfile_kind);
        if !has_expected_lockfile {
            notes.push(format!(
                "declared package manager {manager} does not match present lockfiles near {}",
                manifest.path
            ));
        }
    }

    let package_names = package_identities
        .iter()
        .map(|identity| identity.package_name().to_string())
        .collect::<BTreeSet<_>>();
    if package_names.len() > 1 {
        notes.push(PackageLineageDrift::MixedPackageNames.note().to_string());
    }
    let repeated_identities = package_lineage
        .iter()
        .map(|lineage| lineage.identity.as_str())
        .collect::<BTreeSet<_>>();
    if repeated_identities.len() < package_lineage.len() {
        notes.push(PackageLineageDrift::RepeatedIdentityAcrossPaths.note().to_string());
    }

    notes.sort();
    notes.dedup();
    notes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_types::{LockfileInventoryEntry, ManifestInventoryEntry};

    fn npm_manifest(path: &str, manager: Option<&str>) -> ManifestInventoryEntry {
        ManifestInventoryEntry {
            path: path.to_string(),
            ecosystem: "npm".to_string(),
            manifest_kind: "package_manifest".to_string(),
            declared_package_manager: manager.map(str::to_string),
            direct_dependencies: 1,
            expected_lockfiles: vec!["package-lock.json".to_string()],
        }
    }

    #[test]
    fn lineage_notes_flag_manager_lockfile_mismatch() {
        let notes = derive_lineage_notes(
            &[npm_manifest("/tmp/pkg/package.json", Some("pnpm"))],
            &[LockfileInventoryEntry {
                path: "/tmp/pkg/package-lock.json".to_string(),
                ecosystem: "npm".to_string(),
                lockfile_kind: "package_lock".to_string(),
                ..LockfileInventoryEntry::default()
            }],
            &[PackageIdentity::new("demo", "1.0.0")],
            &[PackageIdentityLineage::new("demo@1.0.0", "/tmp/pkg/package.json")],
        );
        assert!(notes
            .iter()
            .any(|note| note.contains("declared package manager pnpm does not match")));
    }

    #[test]
    fn lineage_notes_flag_repeated_identities_across_paths() {
        let notes = derive_lineage_notes(
            &[npm_manifest("/tmp/pkg-a/package.json", None)],
            &[],
            &[PackageIdentity::new("demo", "1.0.0")],
            &[
                PackageIdentityLineage::new("demo@1.0.0", "/tmp/pkg-a/package.json"),
                PackageIdentityLineage::new("demo@1.0.0", "/tmp/pkg-b/package.json"),
            ],
        );
        assert!(notes.iter().any(|note| note.contains("same package identity")));
    }
}
