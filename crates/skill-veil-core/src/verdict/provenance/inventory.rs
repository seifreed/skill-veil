pub(super) mod identity;
pub(super) mod lockfiles;
pub(super) mod manifests;

use super::publisher::extract_publishers;
use crate::artifact_graph::ArtifactGraph;
use crate::domain_types::{
    LockfileInventoryEntry, ManifestInventoryEntry, PackageIdentity, PackageIdentityLineage,
};

use self::{
    identity::derive_package_identity, lockfiles::derive_lockfile_inventory,
    manifests::derive_manifest_inventory,
};

#[derive(Debug, Default)]
pub(super) struct ProvenanceInventory {
    pub(super) manifests: Vec<ManifestInventoryEntry>,
    pub(super) lockfiles: Vec<LockfileInventoryEntry>,
    pub(super) package_identities: Vec<PackageIdentity>,
    pub(super) publishers: Vec<String>,
    pub(super) package_lineage: Vec<PackageIdentityLineage>,
}

pub(super) fn collect_provenance_inventory(artifact_graph: &ArtifactGraph) -> ProvenanceInventory {
    let mut inventory = ProvenanceInventory::default();

    for node in &artifact_graph.nodes {
        ingest_graph_node(&node.path, &mut inventory);
    }

    finalize_inventory(inventory)
}

fn sort_and_dedup<T: Ord>(values: &mut Vec<T>) {
    values.sort();
    values.dedup();
}

fn extend_unique<T: PartialEq>(target: &mut Vec<T>, items: impl IntoIterator<Item = T>) {
    for item in items {
        if !target.contains(&item) {
            target.push(item);
        }
    }
}

fn collect_node_inventory(
    path: &str,
    content: &str,
    inventory: &mut ProvenanceInventory,
) {
    collect_manifest_inventory(path, content, inventory);
    collect_lockfile_inventory(path, content, inventory);
    collect_package_identity(path, content, inventory);
    collect_publishers(path, content, inventory);
}

fn ingest_graph_node(path: &str, inventory: &mut ProvenanceInventory) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    collect_node_inventory(path, &content, inventory);
}

fn collect_manifest_inventory(path: &str, content: &str, inventory: &mut ProvenanceInventory) {
    if let Some(manifest) = derive_manifest_inventory(path, content) {
        inventory.manifests.push(manifest);
    }
}

fn collect_lockfile_inventory(path: &str, content: &str, inventory: &mut ProvenanceInventory) {
    if let Some(lockfile) = derive_lockfile_inventory(path, content) {
        inventory.lockfiles.push(lockfile);
    }
}

fn collect_package_identity(path: &str, content: &str, inventory: &mut ProvenanceInventory) {
    if let Some(identity) = derive_package_identity(path, content) {
        record_package_identity(inventory, identity, path);
    }
}

fn collect_publishers(path: &str, content: &str, inventory: &mut ProvenanceInventory) {
    extend_unique(&mut inventory.publishers, extract_publishers(path, content));
}

fn finalize_inventory(mut inventory: ProvenanceInventory) -> ProvenanceInventory {
    finalize_shared_lists(&mut inventory);
    inventory
}

fn record_package_identity(
    inventory: &mut ProvenanceInventory,
    identity: PackageIdentity,
    path: &str,
) {
    inventory.package_lineage.push(PackageIdentityLineage::new(
        identity.to_string(),
        path.to_string(),
    ));
    inventory.package_identities.push(identity);
}

fn finalize_shared_lists(inventory: &mut ProvenanceInventory) {
    sort_and_dedup(&mut inventory.package_identities);
    sort_and_dedup(&mut inventory.package_lineage);
    sort_and_dedup(&mut inventory.publishers);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::ArtifactKind;
    use std::fs;

    #[test]
    fn provenance_inventory_deduplicates_publishers_and_identities() {
        let root = tempfile::tempdir().expect("tempdir");
        let manifest_path = root.path().join("package.json");
        let second_path = root.path().join("Cargo.toml");

        fs::write(
            &manifest_path,
            r#"{"name":"demo","version":"1.0.0","author":"demo-publisher"}"#,
        )
        .expect("write package manifest");
        fs::write(
            &second_path,
            r#"
[package]
name = "demo"
version = "1.0.0"
authors = ["demo-publisher"]
"#,
        )
        .expect("write cargo manifest");

        let mut graph = ArtifactGraph::new();
        graph.add_node(
            manifest_path.to_string_lossy().into_owned(),
            ArtifactKind::PackageManifest,
        );
        graph.add_node(
            second_path.to_string_lossy().into_owned(),
            ArtifactKind::PackageManifest,
        );

        let inventory = collect_provenance_inventory(&graph);
        assert_eq!(inventory.publishers, vec!["demo-publisher".to_string()]);
        assert_eq!(inventory.package_identities.len(), 1);
        assert_eq!(inventory.package_lineage.len(), 2);
    }

    #[test]
    fn sort_and_dedup_normalizes_repeated_values() {
        let mut values = vec!["b".to_string(), "a".to_string(), "b".to_string()];
        sort_and_dedup(&mut values);
        assert_eq!(values, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn extend_unique_preserves_first_seen_order_before_sorting() {
        let mut values = vec!["alice".to_string()];
        extend_unique(
            &mut values,
            vec!["alice".to_string(), "bob".to_string(), "alice".to_string()],
        );
        assert_eq!(values, vec!["alice".to_string(), "bob".to_string()]);
    }

    #[test]
    fn collect_node_inventory_accumulates_manifest_identity_and_publishers() {
        let mut inventory = ProvenanceInventory::default();

        collect_node_inventory(
            "package.json",
            r#"{"name":"demo","version":"1.0.0","author":"publisher-a","dependencies":{"left-pad":"1.0.0"}}"#,
            &mut inventory,
        );

        assert_eq!(inventory.manifests.len(), 1);
        assert_eq!(inventory.package_identities.len(), 1);
        assert_eq!(inventory.package_lineage.len(), 1);
        assert_eq!(inventory.publishers, vec!["publisher-a".to_string()]);
    }

    #[test]
    fn finalize_inventory_sorts_and_deduplicates_shared_lists() {
        let inventory = finalize_inventory(ProvenanceInventory {
            manifests: Vec::new(),
            lockfiles: Vec::new(),
            package_identities: vec![
                PackageIdentity::new("b", "1.0.0"),
                PackageIdentity::new("a", "1.0.0"),
                PackageIdentity::new("b", "1.0.0"),
            ],
            publishers: vec!["z".to_string(), "a".to_string(), "z".to_string()],
            package_lineage: vec![
                PackageIdentityLineage::new("b@1.0.0", "b"),
                PackageIdentityLineage::new("a@1.0.0", "a"),
                PackageIdentityLineage::new("b@1.0.0", "b"),
            ],
        });

        assert_eq!(
            inventory.package_identities,
            vec![
                PackageIdentity::new("a", "1.0.0"),
                PackageIdentity::new("b", "1.0.0"),
            ]
        );
        assert_eq!(inventory.publishers, vec!["a".to_string(), "z".to_string()]);
        assert_eq!(inventory.package_lineage.len(), 2);
    }

    #[test]
    fn ingest_graph_node_ignores_missing_files_without_mutating_inventory() {
        let mut inventory = ProvenanceInventory::default();
        ingest_graph_node("/tmp/skill-veil-definitely-missing-manifest.json", &mut inventory);
        assert!(inventory.manifests.is_empty());
        assert!(inventory.lockfiles.is_empty());
        assert!(inventory.package_identities.is_empty());
        assert!(inventory.publishers.is_empty());
        assert!(inventory.package_lineage.is_empty());
    }

    #[test]
    fn ingest_graph_node_reads_existing_manifest_into_inventory() {
        let root = tempfile::tempdir().expect("tempdir");
        let manifest_path = root.path().join("package.json");
        fs::write(
            &manifest_path,
            r#"{"name":"demo","version":"1.0.0","author":"publisher-a"}"#,
        )
        .expect("write manifest");

        let mut inventory = ProvenanceInventory::default();
        ingest_graph_node(manifest_path.to_string_lossy().as_ref(), &mut inventory);

        assert_eq!(inventory.manifests.len(), 1);
        assert_eq!(inventory.package_identities.len(), 1);
        assert_eq!(inventory.publishers, vec!["publisher-a".to_string()]);
    }

    #[test]
    fn collect_package_identity_only_adds_lineage_when_identity_exists() {
        let mut inventory = ProvenanceInventory::default();
        collect_package_identity("README.md", "# no package identity", &mut inventory);
        assert!(inventory.package_identities.is_empty());
        assert!(inventory.package_lineage.is_empty());
    }

    #[test]
    fn collect_manifest_inventory_ignores_non_manifest_content() {
        let mut inventory = ProvenanceInventory::default();
        collect_manifest_inventory("notes.txt", "plain text only", &mut inventory);
        assert!(inventory.manifests.is_empty());
    }

    #[test]
    fn collect_publishers_extends_unique_publishers_only_once() {
        let mut inventory = ProvenanceInventory::default();
        collect_publishers(
            "package.json",
            r#"{"author":"publisher-a","contributors":["publisher-a","publisher-b"]}"#,
            &mut inventory,
        );
        collect_publishers(
            "Cargo.toml",
            "[package]\nauthors = [\"publisher-b\"]\n",
            &mut inventory,
        );

        assert_eq!(
            inventory.publishers,
            vec!["publisher-a".to_string(), "publisher-b".to_string()]
        );
    }

    #[test]
    fn record_package_identity_adds_identity_and_lineage_together() {
        let mut inventory = ProvenanceInventory::default();
        record_package_identity(
            &mut inventory,
            PackageIdentity::new("demo", "1.0.0"),
            "/tmp/package.json",
        );
        assert_eq!(inventory.package_identities.len(), 1);
        assert_eq!(inventory.package_lineage.len(), 1);
        assert_eq!(inventory.package_lineage[0].identity, "demo@1.0.0");
    }

    #[test]
    fn finalize_shared_lists_normalizes_publishers_and_identities_in_place() {
        let mut inventory = ProvenanceInventory {
            manifests: Vec::new(),
            lockfiles: Vec::new(),
            package_identities: vec![
                PackageIdentity::new("b", "1.0.0"),
                PackageIdentity::new("a", "1.0.0"),
            ],
            publishers: vec!["b".to_string(), "a".to_string(), "b".to_string()],
            package_lineage: vec![
                PackageIdentityLineage::new("b@1.0.0", "b"),
                PackageIdentityLineage::new("a@1.0.0", "a"),
            ],
        };

        finalize_shared_lists(&mut inventory);
        assert_eq!(inventory.package_identities[0], PackageIdentity::new("a", "1.0.0"));
        assert_eq!(inventory.publishers, vec!["a".to_string(), "b".to_string()]);
    }
}
