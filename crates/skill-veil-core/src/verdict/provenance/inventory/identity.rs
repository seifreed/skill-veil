use crate::domain_types::PackageIdentity;

pub(super) fn derive_package_identity(path: &str, content: &str) -> Option<PackageIdentity> {
    let file_name = std::path::Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())?
        .to_ascii_lowercase();

    match file_name.as_str() {
        "package.json" | "composer.json" => serde_json::from_str::<serde_json::Value>(content)
            .ok()
            .and_then(|json| {
                let name = json.get("name").and_then(serde_json::Value::as_str)?;
                let version = json
                    .get("version")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                Some(PackageIdentity::new(name, version))
            }),
        "pyproject.toml" | "cargo.toml" => toml::from_str::<toml::Value>(content)
            .ok()
            .and_then(|toml| {
                let package = toml
                    .get("project")
                    .or_else(|| toml.get("package"))
                    .or_else(|| toml.get("tool").and_then(|tool| tool.get("poetry")))?;
                let name = package.get("name").and_then(toml::Value::as_str)?;
                let version = package
                    .get("version")
                    .and_then(toml::Value::as_str)
                    .unwrap_or("unknown");
                Some(PackageIdentity::new(name, version))
            }),
        "go.mod" => content.lines().find_map(|line| {
            line.trim()
                .strip_prefix("module ")
                .map(|module| PackageIdentity::workspace(module.trim()))
        }),
        "gemfile" => content.lines().find_map(|line| {
            line.trim().strip_prefix("source ").map(|source| {
                let trimmed = source.trim();
                PackageIdentity::workspace(format!("gem-source:{trimmed}"))
            })
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_json_identity_uses_declared_name_and_version() {
        let identity = derive_package_identity(
            "/tmp/package.json",
            r#"{"name":"skill-veil","version":"1.2.3"}"#,
        )
        .expect("identity");
        assert_eq!(identity.to_string(), "skill-veil@1.2.3");
        assert_eq!(identity.package_name(), "skill-veil");
    }

    #[test]
    fn go_mod_identity_becomes_workspace_marker() {
        let identity = derive_package_identity("/tmp/go.mod", "module github.com/acme/tool\n")
            .expect("identity");
        assert_eq!(identity.to_string(), "github.com/acme/tool@workspace");
    }
}
