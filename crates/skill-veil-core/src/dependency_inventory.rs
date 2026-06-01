//! Offline dependency inventory extracted from package manifests.
//!
//! The scanner already flags *unpinned* dependencies, but discards the
//! name/version pair afterwards. This module re-reads the manifests and
//! collects the full `(name, version, ecosystem)` set so a downstream,
//! network-enabled enrichment stage (the CLI's OSV.dev client) can look up
//! known CVEs. It is pure and offline — the core never makes network calls.
//!
//! Versions are only retained when they are an exact pin (`requests==2.31.0`,
//! `"chalk": "5.0.0"`). Range specifiers (`^1.0`, `>=2,<3`, `latest`, git
//! URLs), wildcards (`1.x`, `2.0.x`), and — for the npm/Cargo/Poetry range
//! grammars — bare partials (`1`, `1.2`, which mean `^1`/`^1.2`) yield
//! `version: None`; the consumer queries the package without a version in
//! that case rather than sending OSV a literal it cannot resolve.

use serde::{Deserialize, Serialize};

/// Package ecosystem, mapped to the identifiers OSV.dev expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ecosystem {
    PyPI,
    Npm,
    CratesIo,
}

impl Ecosystem {
    /// The exact ecosystem string the OSV.dev API expects.
    #[must_use]
    pub fn osv_name(self) -> &'static str {
        match self {
            Ecosystem::PyPI => "PyPI",
            Ecosystem::Npm => "npm",
            Ecosystem::CratesIo => "crates.io",
        }
    }
}

/// One declared dependency from a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedDependency {
    pub name: String,
    /// Exact pinned version, or `None` when the spec is a range / tag / URL.
    pub version: Option<String>,
    pub ecosystem: Ecosystem,
    /// Manifest the dependency was declared in (display path).
    pub source_artifact: String,
}

/// Collect dependencies from a manifest, dispatching by file name. Returns an
/// empty vector for files that are not recognised dependency manifests.
#[must_use]
pub fn collect_for_manifest(
    file_name: &str,
    content: &str,
    source_artifact: &str,
) -> Vec<ParsedDependency> {
    let lower = file_name.to_ascii_lowercase();
    match lower.as_str() {
        "requirements.txt" => collect_requirements_txt(content, source_artifact),
        "pyproject.toml" => collect_pyproject(content, source_artifact),
        "package.json" => collect_package_json(content, source_artifact),
        "cargo.toml" => collect_cargo(content, source_artifact),
        _ => Vec::new(),
    }
}

/// An exact pin is a leading digit with no range/comparison/wildcard
/// syntax. Used for versions already isolated to the right of a PyPI `==`
/// operator, where a partial release (`==2.31`) is still an exact match.
fn exact_version(spec: &str) -> Option<String> {
    let s = spec.trim().trim_start_matches(['=', 'v']).trim();
    if s.is_empty() {
        return None;
    }
    let first_ok = s.as_bytes().first().is_some_and(u8::is_ascii_digit);
    let clean = s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+' | b'_'));
    if first_ok && clean && !has_wildcard_component(s) {
        Some(s.to_string())
    } else {
        None
    }
}

/// A wildcard component (`*`, `x`, or `X` as a standalone version segment)
/// makes a spec a range, never an exact pin — `1.x`, `2.0.x`, `1.*` all
/// match a family of releases. OSV's `version` field needs a concrete
/// release, so a wildcard spec sent as a literal resolves to nothing and
/// silently misses advisories.
fn has_wildcard_component(s: &str) -> bool {
    s.split(['.', '-', '+'])
        .any(|component| matches!(component, "*" | "x" | "X"))
}

/// An exact semver release pin: `MAJOR.MINOR.PATCH` (all numeric) with an
/// optional `-prerelease` / `+build` suffix. npm, Cargo, and Poetry treat
/// the bare spec string as a *range* grammar — `1`, `1.2`, and `^1.2` are
/// all ranges, not pins — so only a full three-component release counts as
/// an OSV-queryable exact version. Anything looser yields `None`, and the
/// consumer queries the package without a version rather than sending a
/// literal OSV cannot resolve.
fn exact_semver_pin(spec: &str) -> Option<String> {
    let pin = exact_version(spec)?;
    let core = pin.split(['-', '+']).next().unwrap_or(&pin);
    let mut parts = core.split('.');
    let (Some(major), Some(minor), Some(patch), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let numeric = |c: &str| !c.is_empty() && c.bytes().all(|b| b.is_ascii_digit());
    (numeric(major) && numeric(minor) && numeric(patch)).then_some(pin)
}

fn push_dep(
    out: &mut Vec<ParsedDependency>,
    name: &str,
    version: Option<String>,
    ecosystem: Ecosystem,
    source_artifact: &str,
) {
    let name = name.trim();
    if name.is_empty() {
        return;
    }
    let dep = ParsedDependency {
        name: name.to_string(),
        version,
        ecosystem,
        source_artifact: source_artifact.to_string(),
    };
    if !out.contains(&dep) {
        out.push(dep);
    }
}

fn collect_requirements_txt(content: &str, source: &str) -> Vec<ParsedDependency> {
    let mut out = Vec::new();
    for raw in content.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('-') || line.contains("://") {
            continue;
        }
        // Cut PEP 508 environment markers and extras.
        let spec = line.split(';').next().unwrap_or(line).trim();
        let name_end = spec
            .find(['=', '>', '<', '~', '!', '[', ' ', '@'])
            .unwrap_or(spec.len());
        let name = spec[..name_end].trim();
        let version = spec[name_end..]
            .split_once("==")
            .and_then(|(_, v)| exact_version(v.split([',', ';', ' ']).next().unwrap_or(v)));
        push_dep(&mut out, name, version, Ecosystem::PyPI, source);
    }
    out
}

fn collect_package_json(content: &str, source: &str) -> Vec<ParsedDependency> {
    let mut out = Vec::new();
    let Ok(json) = serde_json::from_str::<serde_json::Value>(content) else {
        return out;
    };
    for field in ["dependencies", "devDependencies", "optionalDependencies"] {
        let Some(map) = json.get(field).and_then(serde_json::Value::as_object) else {
            continue;
        };
        for (name, spec) in map {
            let version = spec.as_str().and_then(exact_semver_pin);
            push_dep(&mut out, name, version, Ecosystem::Npm, source);
        }
    }
    out
}

fn collect_cargo(content: &str, source: &str) -> Vec<ParsedDependency> {
    let mut out = Vec::new();
    let Ok(value) = content.parse::<toml::Value>() else {
        return out;
    };
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        let Some(table) = value.get(section).and_then(toml::Value::as_table) else {
            continue;
        };
        for (name, spec) in table {
            let version = match spec {
                toml::Value::String(s) => exact_semver_pin(s),
                toml::Value::Table(t) => t
                    .get("version")
                    .and_then(toml::Value::as_str)
                    .and_then(exact_semver_pin),
                _ => None,
            };
            push_dep(&mut out, name, version, Ecosystem::CratesIo, source);
        }
    }
    out
}

fn collect_pyproject(content: &str, source: &str) -> Vec<ParsedDependency> {
    let mut out = Vec::new();
    let Ok(value) = content.parse::<toml::Value>() else {
        return out;
    };
    // PEP 621: [project] dependencies = ["requests==2.31.0", ...]
    if let Some(deps) = value
        .get("project")
        .and_then(|p| p.get("dependencies"))
        .and_then(toml::Value::as_array)
    {
        for entry in deps.iter().filter_map(toml::Value::as_str) {
            for dep in collect_requirements_txt(entry, source) {
                push_dep(&mut out, &dep.name, dep.version, Ecosystem::PyPI, source);
            }
        }
    }
    // Poetry: [tool.poetry.dependencies] name = "^1.0" | { version = "1.0" }
    if let Some(table) = value
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.get("dependencies"))
        .and_then(toml::Value::as_table)
    {
        for (name, spec) in table {
            if name.eq_ignore_ascii_case("python") {
                continue;
            }
            let version = match spec {
                toml::Value::String(s) => exact_semver_pin(s),
                toml::Value::Table(t) => t
                    .get("version")
                    .and_then(toml::Value::as_str)
                    .and_then(exact_semver_pin),
                _ => None,
            };
            push_dep(&mut out, name, version, Ecosystem::PyPI, source);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(deps: &[ParsedDependency]) -> Vec<&str> {
        deps.iter().map(|d| d.name.as_str()).collect()
    }

    #[test]
    fn requirements_collects_pinned_and_unpinned() {
        let content = "requests==2.31.0\nflask>=2.0\n# comment\nhttpx\n-r other.txt\n";
        let deps = collect_requirements_txt(content, "/r.txt");
        assert_eq!(names(&deps), vec!["requests", "flask", "httpx"]);
        let requests = deps.iter().find(|d| d.name == "requests").unwrap();
        assert_eq!(requests.version.as_deref(), Some("2.31.0"));
        assert_eq!(
            deps.iter().find(|d| d.name == "flask").unwrap().version,
            None
        );
        assert!(deps.iter().all(|d| d.ecosystem == Ecosystem::PyPI));
    }

    #[test]
    fn requirements_handles_extras_and_markers() {
        let deps = collect_requirements_txt(
            "requests[security]==2.31.0 ; python_version>='3.8'\n",
            "/r.txt",
        );
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "requests");
        assert_eq!(deps[0].version.as_deref(), Some("2.31.0"));
    }

    #[test]
    fn package_json_collects_all_dependency_sections() {
        let content = r#"{
          "dependencies": { "chalk": "5.0.0", "lodash": "^4.17.21" },
          "devDependencies": { "jest": "29.0.0" }
        }"#;
        let deps = collect_package_json(content, "/package.json");
        assert_eq!(deps.len(), 3);
        assert_eq!(
            deps.iter()
                .find(|d| d.name == "chalk")
                .unwrap()
                .version
                .as_deref(),
            Some("5.0.0")
        );
        // Range specifier -> no exact version.
        assert_eq!(
            deps.iter().find(|d| d.name == "lodash").unwrap().version,
            None
        );
        assert!(deps.iter().all(|d| d.ecosystem == Ecosystem::Npm));
    }

    #[test]
    fn cargo_collects_string_and_table_specs() {
        let content = "[dependencies]\nserde = \"1.0.200\"\ntokio = { version = \"1.40.0\", features = [\"full\"] }\nlocal = { path = \"../local\" }\n";
        let deps = collect_cargo(content, "/Cargo.toml");
        assert_eq!(
            deps.iter()
                .find(|d| d.name == "serde")
                .unwrap()
                .version
                .as_deref(),
            Some("1.0.200")
        );
        assert_eq!(
            deps.iter()
                .find(|d| d.name == "tokio")
                .unwrap()
                .version
                .as_deref(),
            Some("1.40.0")
        );
        // Path dependency has no version.
        assert_eq!(
            deps.iter().find(|d| d.name == "local").unwrap().version,
            None
        );
        assert!(deps.iter().all(|d| d.ecosystem == Ecosystem::CratesIo));
    }

    #[test]
    fn pyproject_collects_pep621_and_poetry() {
        let content = r#"
[project]
dependencies = ["requests==2.31.0", "rich>=13"]

[tool.poetry.dependencies]
python = "^3.10"
httpx = "0.27.0"
flask = { version = "3.0.0" }
"#;
        let deps = collect_pyproject(content, "/pyproject.toml");
        let n = names(&deps);
        assert!(n.contains(&"requests") && n.contains(&"rich"));
        assert!(n.contains(&"httpx") && n.contains(&"flask"));
        assert!(
            !n.contains(&"python"),
            "the python constraint is not a package"
        );
        assert_eq!(
            deps.iter()
                .find(|d| d.name == "httpx")
                .unwrap()
                .version
                .as_deref(),
            Some("0.27.0")
        );
    }

    #[test]
    fn dispatch_by_file_name_is_case_insensitive() {
        let deps = collect_for_manifest("Requirements.txt", "requests==2.31.0\n", "/x");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ecosystem, Ecosystem::PyPI);
    }

    #[test]
    fn unknown_manifest_yields_nothing() {
        assert!(collect_for_manifest("README.md", "requests==2.0", "/x").is_empty());
    }

    #[test]
    fn osv_ecosystem_names_match_api() {
        assert_eq!(Ecosystem::PyPI.osv_name(), "PyPI");
        assert_eq!(Ecosystem::Npm.osv_name(), "npm");
        assert_eq!(Ecosystem::CratesIo.osv_name(), "crates.io");
    }

    #[test]
    fn malformed_manifest_does_not_panic() {
        assert!(collect_package_json("{ not json", "/x").is_empty());
        assert!(collect_cargo("not = = toml", "/x").is_empty());
    }

    /// Contract: an npm spec that is a wildcard (`1.x`, `2.0.x`) or a
    /// partial version (`1`, `1.2`) is a RANGE, not an exact pin, so it
    /// yields `version: None` and the OSV consumer queries the package
    /// without a version. Pre-fix these passed the "clean characters"
    /// gate and were sent to OSV as literal versions it cannot resolve,
    /// silently missing advisories on the matched release line.
    #[test]
    fn npm_wildcard_and_partial_specs_are_not_exact_pins() {
        let content = r#"{
          "dependencies": {
            "wild": "1.x",
            "wild2": "2.0.x",
            "partial": "1.2",
            "major": "1",
            "exact": "1.2.3"
          }
        }"#;
        let deps = collect_package_json(content, "/package.json");
        for name in ["wild", "wild2", "partial", "major"] {
            assert_eq!(
                deps.iter().find(|d| d.name == name).unwrap().version,
                None,
                "{name} is a range and must not be queried as an exact version",
            );
        }
        assert_eq!(
            deps.iter()
                .find(|d| d.name == "exact")
                .unwrap()
                .version
                .as_deref(),
            Some("1.2.3"),
            "a full semver release is still an exact pin",
        );
    }

    /// Contract: a bare partial Cargo version (`1.2`) is the `^1.2` range,
    /// not a pin. Only a full `MAJOR.MINOR.PATCH` release counts.
    #[test]
    fn cargo_partial_version_is_not_an_exact_pin() {
        let content = "[dependencies]\npartial = \"1.2\"\nexact = \"1.2.3\"\n";
        let deps = collect_cargo(content, "/Cargo.toml");
        assert_eq!(
            deps.iter().find(|d| d.name == "partial").unwrap().version,
            None
        );
        assert_eq!(
            deps.iter()
                .find(|d| d.name == "exact")
                .unwrap()
                .version
                .as_deref(),
            Some("1.2.3")
        );
    }

    /// Contract: a PyPI `==` constraint is an exact match even when the
    /// version is partial (`requests==2.31`), so it is preserved — the
    /// stricter semver rule applies only to ecosystems whose bare spec is
    /// a range grammar (npm / Cargo / Poetry), never to a value already
    /// isolated to the right of `==`. A `==1.x` wildcard is still rejected.
    #[test]
    fn pypi_double_equals_partial_is_exact_but_wildcard_is_not() {
        let deps = collect_requirements_txt("requests==2.31\n", "/r.txt");
        assert_eq!(deps[0].version.as_deref(), Some("2.31"));

        let wild = collect_requirements_txt("flask==1.x\n", "/r.txt");
        assert_eq!(wild[0].version, None, "a wildcard is a range even after ==",);
    }
}
