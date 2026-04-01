use crate::domain_types::LockfileInventoryEntry;
use regex::Regex;
use std::sync::LazyLock;

static RE_LOCKFILE_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"https?://[^\s"']+"#).expect("valid regex"));

pub(super) fn derive_lockfile_inventory(
    path: &str,
    content: &str,
) -> Option<LockfileInventoryEntry> {
    let file_name = std::path::Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())?
        .to_ascii_lowercase();
    let (ecosystem, lockfile_kind) = match file_name.as_str() {
        "package-lock.json" | "npm-shrinkwrap.json" => ("npm", "package_lock"),
        "pnpm-lock.yaml" => ("npm", "pnpm_lock"),
        "yarn.lock" => ("npm", "yarn_lock"),
        "cargo.lock" => ("rust", "cargo_lock"),
        "poetry.lock" => ("python", "poetry_lock"),
        "uv.lock" => ("python", "uv_lock"),
        "pipfile.lock" => ("python", "pipfile_lock"),
        "go.sum" => ("go", "go_sum"),
        "composer.lock" => ("php", "composer_lock"),
        _ => return None,
    };

    let resolved_urls = extract_lockfile_urls(content);
    let hashes_present = lockfile_contains_hashes(&file_name, content);
    let (direct_dependencies, transitive_dependencies) =
        count_lockfile_dependencies(&file_name, content);
    Some(LockfileInventoryEntry {
        path: path.to_string(),
        ecosystem: ecosystem.to_string(),
        lockfile_kind: lockfile_kind.to_string(),
        direct_dependencies,
        transitive_dependencies,
        resolved_urls,
        hashes_present,
    })
}

fn extract_lockfile_urls(content: &str) -> Vec<String> {
    let mut urls: Vec<_> = RE_LOCKFILE_URL
        .find_iter(content)
        .map(|matched| {
            matched
                .as_str()
                .trim_end_matches('"')
                .trim_end_matches('\'')
                .to_string()
        })
        .collect();
    urls.sort();
    urls.dedup();
    urls
}

fn lockfile_contains_hashes(file_name: &str, content: &str) -> bool {
    match file_name {
        "package-lock.json" | "npm-shrinkwrap.json" => content.contains("\"integrity\""),
        "pnpm-lock.yaml" => content.contains("integrity:"),
        "yarn.lock" => content.contains("integrity "),
        "cargo.lock" => content.contains("checksum = "),
        "poetry.lock" | "uv.lock" | "pipfile.lock" => {
            content.contains("sha256:") || content.contains("\"hashes\"")
        }
        "go.sum" => !content.trim().is_empty(),
        "composer.lock" => content.contains("\"shasum\""),
        _ => false,
    }
}

fn count_lockfile_dependencies(file_name: &str, content: &str) -> (usize, usize) {
    match file_name {
        "package-lock.json" | "npm-shrinkwrap.json" => {
            serde_json::from_str::<serde_json::Value>(content)
                .ok()
                .map(|json| {
                    let package_count = json
                        .get("packages")
                        .and_then(serde_json::Value::as_object)
                        .map_or(0, |map| map.len().saturating_sub(1));
                    let direct = json
                        .get("dependencies")
                        .and_then(serde_json::Value::as_object)
                        .map_or(0, |map| map.len());
                    (direct, package_count.saturating_sub(direct))
                })
                .unwrap_or((0, 0))
        }
        "pnpm-lock.yaml" => {
            let direct = count_yaml_map_items(content, "importers");
            let transitive = count_yaml_map_items(content, "packages");
            (direct, transitive)
        }
        "yarn.lock" => {
            let total = content
                .lines()
                .filter(|line| line.ends_with(':') && !line.starts_with(' ') && !line.is_empty())
                .count();
            (0, total)
        }
        "cargo.lock" | "poetry.lock" | "uv.lock" => {
            let total = content.matches("[[package]]").count();
            (0, total)
        }
        "go.sum" => {
            let total = content
                .lines()
                .filter(|line| !line.trim().is_empty())
                .count();
            (0, total)
        }
        "pipfile.lock" => serde_json::from_str::<serde_json::Value>(content)
            .ok()
            .map(|json| {
                let default = json
                    .get("default")
                    .and_then(serde_json::Value::as_object)
                    .map_or(0, |map| map.len());
                let develop = json
                    .get("develop")
                    .and_then(serde_json::Value::as_object)
                    .map_or(0, |map| map.len());
                (default + develop, 0)
            })
            .unwrap_or((0, 0)),
        "composer.lock" => serde_json::from_str::<serde_json::Value>(content)
            .ok()
            .map(|json| {
                let direct = json
                    .get("packages")
                    .and_then(serde_json::Value::as_array)
                    .map_or(0, |items| items.len());
                let dev = json
                    .get("packages-dev")
                    .and_then(serde_json::Value::as_array)
                    .map_or(0, |items| items.len());
                (direct + dev, 0)
            })
            .unwrap_or((0, 0)),
        _ => (0, 0),
    }
}

fn count_yaml_map_items(content: &str, key: &str) -> usize {
    serde_yaml::from_str::<serde_yaml::Value>(content)
        .ok()
        .and_then(|yaml| {
            yaml.get(key)
                .and_then(serde_yaml::Value::as_mapping)
                .cloned()
        })
        .map_or(0, |mapping| mapping.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_lock_inventory_extracts_urls_and_hash_presence() {
        let lockfile = derive_lockfile_inventory(
            "/tmp/package-lock.json",
            r#"{
  "dependencies":{"left-pad":{"version":"1.0.0"}},
  "packages":{"":{"name":"root"},"node_modules/left-pad":{"resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz","integrity":"sha512-abc"}}
}"#,
        )
        .expect("lockfile");
        assert_eq!(lockfile.direct_dependencies, 1);
        assert!(lockfile.hashes_present);
        assert_eq!(
            lockfile.resolved_urls,
            vec!["https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz"]
        );
    }

    #[test]
    fn pnpm_lock_counts_importers_and_packages() {
        let lockfile = derive_lockfile_inventory(
            "/tmp/pnpm-lock.yaml",
            r#"
importers:
  .:
    specifiers: {}
packages:
  left-pad@1.0.0:
    resolution:
      integrity: sha512-abc
"#,
        )
        .expect("lockfile");
        assert_eq!(lockfile.direct_dependencies, 1);
        assert_eq!(lockfile.transitive_dependencies, 1);
        assert!(lockfile.hashes_present);
    }

    #[test]
    fn go_sum_inventory_treats_non_empty_file_as_hashed_transitive_set() {
        let lockfile = derive_lockfile_inventory(
            "/tmp/go.sum",
            "github.com/pkg/errors v0.9.1 h1:abc\ngithub.com/pkg/errors v0.9.1/go.mod h1:def\n",
        )
        .expect("lockfile");
        assert_eq!(lockfile.direct_dependencies, 0);
        assert_eq!(lockfile.transitive_dependencies, 2);
        assert!(lockfile.hashes_present);
    }
}
