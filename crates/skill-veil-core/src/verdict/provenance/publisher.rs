use crate::domain_types::PublisherConsistency;

pub(super) fn derive_publisher_consistency(publishers: &[String]) -> PublisherConsistency {
    match publishers.len() {
        0 => PublisherConsistency::Unknown,
        1 => PublisherConsistency::Consistent,
        _ => PublisherConsistency::Mixed,
    }
}

pub(super) fn is_malicious_publisher(publisher: &str) -> bool {
    ["hightower6eu"].iter().any(|candidate| {
        publisher.trim().eq_ignore_ascii_case(candidate)
            || publisher
                .to_ascii_lowercase()
                .contains(&candidate.to_ascii_lowercase())
    })
}

pub(super) fn extract_publishers(path: &str, content: &str) -> Vec<String> {
    let file_name = std::path::Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let mut publishers = Vec::new();

    match file_name.as_str() {
        "package.json" | "composer.json" => {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
                collect_json_publisher(&json.get("author"), &mut publishers);
                collect_json_publisher(&json.get("publisher"), &mut publishers);
                collect_json_publisher(&json.get("authors"), &mut publishers);
                collect_json_publisher(&json.get("repository"), &mut publishers);
            }
        }
        "pyproject.toml" | "cargo.toml" => {
            if let Ok(toml) = content.parse::<toml::Value>() {
                collect_toml_publisher(
                    toml.get("project").and_then(|value| value.get("authors")),
                    &mut publishers,
                );
                collect_toml_publisher(
                    toml.get("package").and_then(|value| value.get("authors")),
                    &mut publishers,
                );
                collect_toml_publisher(
                    toml.get("package")
                        .and_then(|value| value.get("repository")),
                    &mut publishers,
                );
                collect_toml_publisher(
                    toml.get("tool").and_then(|value| value.get("poetry")),
                    &mut publishers,
                );
            }
        }
        "go.mod" => {
            for line in content.lines() {
                let trimmed = line.trim();
                if let Some(module) = trimmed.strip_prefix("module ") {
                    publishers.push(module.trim().to_string());
                }
            }
        }
        "gemfile" => {
            for line in content.lines() {
                let trimmed = line.trim();
                if let Some(source) = trimmed.strip_prefix("source ") {
                    publishers.push(
                        source
                            .trim_matches(|ch| ch == '"' || ch == '\'')
                            .trim()
                            .to_string(),
                    );
                }
            }
        }
        _ => {}
    }

    publishers.retain(|publisher| !publisher.trim().is_empty());
    publishers.sort();
    publishers.dedup();
    publishers
}

fn collect_json_publisher(value: &Option<&serde_json::Value>, publishers: &mut Vec<String>) {
    let Some(value) = value else {
        return;
    };
    match value {
        serde_json::Value::String(text) => publishers.push(text.trim().to_string()),
        serde_json::Value::Array(values) => {
            for item in values {
                collect_json_publisher(&Some(item), publishers);
            }
        }
        serde_json::Value::Object(map) => {
            for key in ["name", "email", "url", "type"] {
                if let Some(text) = map.get(key).and_then(|value| value.as_str()) {
                    publishers.push(text.trim().to_string());
                }
            }
        }
        _ => {}
    }
}

fn collect_toml_publisher(value: Option<&toml::Value>, publishers: &mut Vec<String>) {
    let Some(value) = value else {
        return;
    };
    match value {
        toml::Value::String(text) => publishers.push(text.trim().to_string()),
        toml::Value::Array(values) => {
            for item in values {
                collect_toml_publisher(Some(item), publishers);
            }
        }
        toml::Value::Table(table) => {
            for key in ["name", "email", "homepage", "repository"] {
                if let Some(text) = table.get(key).and_then(|value| value.as_str()) {
                    publishers.push(text.trim().to_string());
                }
            }
        }
        _ => {}
    }
}
