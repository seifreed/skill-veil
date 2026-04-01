use crate::domain_types::ManifestInventoryEntry;

pub(super) fn derive_manifest_inventory(
    path: &str,
    content: &str,
) -> Option<ManifestInventoryEntry> {
    let file_name = std::path::Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())?
        .to_ascii_lowercase();
    let (ecosystem, manifest_kind) = match file_name.as_str() {
        "package.json" => ("npm", "package_manifest"),
        "requirements.txt" => ("python", "requirements"),
        "pyproject.toml" => ("python", "pyproject"),
        "cargo.toml" => ("rust", "cargo_manifest"),
        "gemfile" => ("ruby", "gemfile"),
        "go.mod" => ("go", "go_module"),
        "composer.json" => ("php", "composer_manifest"),
        "pnpm-workspace.yaml" => ("npm", "workspace_manifest"),
        _ => return None,
    };

    let direct_dependencies = count_manifest_dependencies(&file_name, content);
    let expected_lockfiles = expected_lockfiles_for_manifest(&file_name, content);
    let declared_package_manager = declared_package_manager(&file_name, content);
    Some(ManifestInventoryEntry {
        path: path.to_string(),
        ecosystem: ecosystem.to_string(),
        manifest_kind: manifest_kind.to_string(),
        declared_package_manager,
        direct_dependencies,
        expected_lockfiles,
    })
}

fn count_manifest_dependencies(file_name: &str, content: &str) -> usize {
    match file_name {
        "package.json" | "composer.json" => serde_json::from_str::<serde_json::Value>(content)
            .ok()
            .and_then(|json| {
                let mut total = 0_usize;
                for key in ["dependencies", "devDependencies", "optionalDependencies"] {
                    total += json
                        .get(key)
                        .and_then(serde_json::Value::as_object)
                        .map_or(0, |map| map.len());
                }
                Some(total)
            })
            .unwrap_or(0),
        "pyproject.toml" => toml::from_str::<toml::Value>(content)
            .ok()
            .map(|toml| {
                toml.get("project")
                    .and_then(|project| project.get("dependencies"))
                    .and_then(toml::Value::as_array)
                    .map_or(0, Vec::len)
                    + toml
                        .get("tool")
                        .and_then(|tool| tool.get("poetry"))
                        .and_then(|poetry| poetry.get("dependencies"))
                        .and_then(toml::Value::as_table)
                        .map_or(0, |table| table.len().saturating_sub(1))
            })
            .unwrap_or(0),
        "cargo.toml" => toml::from_str::<toml::Value>(content)
            .ok()
            .map(|toml| {
                ["dependencies", "dev-dependencies", "build-dependencies"]
                    .into_iter()
                    .map(|key| {
                        toml.get(key)
                            .and_then(toml::Value::as_table)
                            .map_or(0, |table| table.len())
                    })
                    .sum()
            })
            .unwrap_or(0),
        "requirements.txt" => content
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                !trimmed.is_empty() && !trimmed.starts_with('#')
            })
            .count(),
        "gemfile" => content
            .lines()
            .filter(|line| line.trim_start().starts_with("gem "))
            .count(),
        "go.mod" => content
            .lines()
            .filter(|line| {
                let trimmed = line.trim_start();
                trimmed.starts_with("require ") || trimmed.starts_with('\t')
            })
            .count(),
        _ => 0,
    }
}

fn expected_lockfiles_for_manifest(file_name: &str, content: &str) -> Vec<String> {
    match file_name {
        "package.json" => {
            let manager = declared_package_manager(file_name, content);
            if manager.as_deref() == Some("pnpm") {
                vec!["pnpm-lock.yaml".to_string()]
            } else if manager.as_deref() == Some("yarn") {
                vec!["yarn.lock".to_string()]
            } else if manager.as_deref() == Some("npm") {
                vec![
                    "package-lock.json".to_string(),
                    "npm-shrinkwrap.json".to_string(),
                ]
            } else {
                vec![
                    "package-lock.json".to_string(),
                    "npm-shrinkwrap.json".to_string(),
                    "yarn.lock".to_string(),
                ]
            }
        }
        "pyproject.toml" => vec!["poetry.lock".to_string(), "uv.lock".to_string()],
        "cargo.toml" => vec!["Cargo.lock".to_string()],
        "go.mod" => vec!["go.sum".to_string()],
        "gemfile" => vec!["Gemfile.lock".to_string()],
        "composer.json" => vec!["composer.lock".to_string()],
        _ => Vec::new(),
    }
}

fn declared_package_manager(file_name: &str, content: &str) -> Option<String> {
    match file_name {
        "package.json" => serde_json::from_str::<serde_json::Value>(content)
            .ok()
            .and_then(|json| {
                json.get("packageManager")
                    .and_then(serde_json::Value::as_str)
                    .map(|value| {
                        value
                            .split('@')
                            .next()
                            .unwrap_or(value)
                            .to_ascii_lowercase()
                    })
            }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_manager_selects_matching_expected_lockfiles() {
        let manifest = derive_manifest_inventory(
            "/tmp/package.json",
            r#"{"packageManager":"pnpm@9.0.0","dependencies":{"left-pad":"1.0.0"}}"#,
        )
        .expect("manifest");
        assert_eq!(manifest.declared_package_manager.as_deref(), Some("pnpm"));
        assert_eq!(manifest.expected_lockfiles, vec!["pnpm-lock.yaml"]);
        assert_eq!(manifest.direct_dependencies, 1);
    }

    #[test]
    fn cargo_manifest_counts_multiple_dependency_tables() {
        let manifest = derive_manifest_inventory(
            "/tmp/Cargo.toml",
            r#"
[package]
name = "skill-veil"
version = "0.1.0"

[dependencies]
serde = "1"

[dev-dependencies]
tempfile = "3"
"#,
        )
        .expect("manifest");
        assert_eq!(manifest.direct_dependencies, 2);
        assert_eq!(manifest.expected_lockfiles, vec!["Cargo.lock"]);
    }

    #[test]
    fn package_json_without_declared_manager_keeps_multiple_lockfile_options() {
        let manifest = derive_manifest_inventory(
            "/tmp/package.json",
            r#"{"dependencies":{"left-pad":"1.0.0"}}"#,
        )
        .expect("manifest");
        assert_eq!(manifest.declared_package_manager, None);
        assert_eq!(
            manifest.expected_lockfiles,
            vec![
                "package-lock.json".to_string(),
                "npm-shrinkwrap.json".to_string(),
                "yarn.lock".to_string()
            ]
        );
    }
}
