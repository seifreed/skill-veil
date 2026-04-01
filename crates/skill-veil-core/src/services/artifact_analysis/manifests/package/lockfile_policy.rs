use serde_json::Value;
use toml::Value as TomlValue;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PackageJsonLockPolicy {
    Npm,
    Yarn,
    Pnpm,
    Unknown,
}

impl PackageJsonLockPolicy {
    pub(super) fn detect(json: &Value) -> Self {
        let package_manager = json
            .get("packageManager")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();

        if package_manager.starts_with("pnpm@") {
            Self::Pnpm
        } else if package_manager.starts_with("yarn@") {
            Self::Yarn
        } else if package_manager.starts_with("npm@") {
            Self::Npm
        } else {
            Self::Unknown
        }
    }

    pub(super) fn expected_lockfiles(self) -> Vec<&'static str> {
        match self {
            Self::Pnpm => vec!["pnpm-lock.yaml"],
            Self::Yarn => vec!["yarn.lock"],
            Self::Npm => vec!["package-lock.json", "npm-shrinkwrap.json"],
            Self::Unknown => vec![
                "package-lock.json",
                "npm-shrinkwrap.json",
                "yarn.lock",
                "pnpm-lock.yaml",
            ],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PyprojectLockPolicy {
    Poetry,
    Uv,
    Unknown,
}

impl PyprojectLockPolicy {
    pub(super) fn detect(toml: &TomlValue) -> Self {
        if toml
            .get("tool")
            .and_then(|tool| tool.get("poetry"))
            .is_some()
        {
            Self::Poetry
        } else if toml.get("tool").and_then(|tool| tool.get("uv")).is_some() {
            Self::Uv
        } else {
            Self::Unknown
        }
    }

    pub(super) fn expected_lockfiles(self) -> Vec<&'static str> {
        match self {
            Self::Poetry => vec!["poetry.lock"],
            Self::Uv => vec!["uv.lock"],
            Self::Unknown => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_manager_selects_expected_lockfile_family() {
        let json: Value = serde_json::json!({ "packageManager": "pnpm@9.0.0" });
        assert_eq!(PackageJsonLockPolicy::detect(&json), PackageJsonLockPolicy::Pnpm);
    }

    #[test]
    fn pyproject_detects_poetry_lock_policy() {
        let toml: TomlValue = "[tool.poetry]\nname = 'demo'".parse().unwrap();
        assert_eq!(PyprojectLockPolicy::detect(&toml), PyprojectLockPolicy::Poetry);
    }
}
