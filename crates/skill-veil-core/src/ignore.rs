use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct IgnoreMatcher {
    root: PathBuf,
    rules: Vec<IgnoreRule>,
}

#[derive(Debug, Clone)]
struct IgnoreRule {
    negated: bool,
    match_basename: bool,
    original_pattern: String,
    line_number: usize,
    matcher: GlobSet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedPath {
    pub path: String,
    pub reason: String,
    pub pattern: String,
    pub line_number: usize,
}

impl IgnoreMatcher {
    #[must_use]
    pub fn empty(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            rules: Vec::new(),
        }
    }

    pub fn from_file(path: &Path) -> Result<Self, std::io::Error> {
        let root = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let mut rules = Vec::new();
        let mut visited = HashSet::new();
        Self::load_file_rules(path, &mut rules, &mut visited)?;
        Ok(Self { root, rules })
    }

    #[must_use]
    pub fn from_str(root: impl Into<PathBuf>, content: &str) -> Self {
        let root = root.into();
        let mut rules = Vec::new();
        Self::parse_content(Path::new("<inline>"), content, &mut rules);
        Self { root, rules }
    }

    fn load_file_rules(
        path: &Path,
        rules: &mut Vec<IgnoreRule>,
        visited: &mut HashSet<PathBuf>,
    ) -> Result<(), std::io::Error> {
        let canonical_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        if !visited.insert(canonical_path) {
            return Ok(());
        }

        let content = std::fs::read_to_string(path)?;
        Self::parse_content(path, &content, rules);

        for include in Self::included_paths(path, &content) {
            if !include.is_file() {
                continue;
            }
            Self::load_file_rules(&include, rules, visited)?;
        }
        Ok(())
    }

    fn included_paths(path: &Path, content: &str) -> Vec<PathBuf> {
        let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
        content
            .lines()
            .map(str::trim)
            .filter_map(|line| line.strip_prefix(":include").map(str::trim))
            .filter(|include_path| !include_path.is_empty())
            .map(|include_path| base_dir.join(include_path))
            .collect()
    }

    fn parse_content(_path: &Path, content: &str, rules: &mut Vec<IgnoreRule>) {
        for (index, raw_line) in content.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(":include") {
                continue;
            }

            let (negated, mut pattern) = if let Some(rest) = line.strip_prefix('!') {
                (true, rest.trim())
            } else {
                (false, line)
            };

            if pattern.is_empty() {
                continue;
            }

            let directory_only = pattern.ends_with('/');
            if directory_only {
                pattern = pattern.trim_end_matches('/');
            }

            let anchored = pattern.starts_with('/');
            let pattern = pattern.trim_start_matches('/');
            if pattern.is_empty() {
                continue;
            }

            let match_basename = !anchored && !pattern.contains('/');
            let mut builder = GlobSetBuilder::new();
            for glob_pattern in compiled_glob_patterns(pattern, anchored, directory_only) {
                let Ok(glob) = Glob::new(&glob_pattern) else {
                    continue;
                };
                builder.add(glob);
            }
            let Ok(matcher) = builder.build() else {
                continue;
            };

            rules.push(IgnoreRule {
                negated,
                match_basename,
                original_pattern: line.to_string(),
                line_number: index + 1,
                matcher,
            });
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn is_ignored(&self, path: &Path) -> bool {
        self.matching_rule(path).is_some()
    }

    #[must_use]
    pub fn matching_rule(&self, path: &Path) -> Option<SkippedPath> {
        if self.rules.is_empty() {
            return None;
        }

        let relative = path.strip_prefix(&self.root).unwrap_or(path).to_path_buf();
        let basename = relative
            .file_name()
            .map(PathBuf::from)
            .unwrap_or_else(|| relative.clone());

        let mut ignored = false;
        let mut matched_rule = None;
        for rule in &self.rules {
            let matches = if rule.match_basename {
                rule.matcher.is_match(&basename) || rule.matcher.is_match(&relative)
            } else {
                rule.matcher.is_match(&relative)
            };
            if !matches {
                continue;
            }
            ignored = !rule.negated;
            matched_rule = Some(rule);
        }
        if ignored {
            matched_rule.map(|rule| SkippedPath {
                path: path.display().to_string(),
                reason: "ignore_file_match".to_string(),
                pattern: rule.original_pattern.clone(),
                line_number: rule.line_number,
            })
        } else {
            None
        }
    }
}

fn compiled_glob_patterns(pattern: &str, anchored: bool, directory_only: bool) -> Vec<String> {
    let base = if anchored {
        pattern.to_string()
    } else {
        format!("**/{pattern}")
    };

    if directory_only {
        vec![base.clone(), format!("{base}/**")]
    } else {
        vec![base]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn matcher_supports_simple_patterns_and_negation() {
        let matcher = IgnoreMatcher::from_str(
            "/repo",
            r#"
            # comment
            node_modules/
            *.lock
            !safe.lock
            prompts/generated/**
            "#,
        );

        assert!(matcher.is_ignored(Path::new("/repo/node_modules")));
        assert!(matcher.is_ignored(Path::new("/repo/foo.lock")));
        assert!(!matcher.is_ignored(Path::new("/repo/safe.lock")));
        assert!(matcher.is_ignored(Path::new("/repo/prompts/generated/a.md")));
        assert!(!matcher.is_ignored(Path::new("/repo/src/main.rs")));
    }

    #[test]
    fn matcher_supports_semgrepignore_include() {
        let dir = tempdir().unwrap();
        let semgrepignore = dir.path().join(".semgrepignore");
        let gitignore = dir.path().join(".gitignore");

        std::fs::write(&gitignore, "dist/\n").unwrap();
        std::fs::write(&semgrepignore, ":include .gitignore\n").unwrap();

        let matcher = IgnoreMatcher::from_file(&semgrepignore).unwrap();
        assert!(matcher.is_ignored(&dir.path().join("dist/output.md")));
    }

    #[test]
    fn matcher_supports_nested_include_and_negation() {
        let dir = tempdir().unwrap();
        let semgrepignore = dir.path().join(".semgrepignore");
        let config_dir = dir.path().join(".config");
        std::fs::create_dir_all(&config_dir).unwrap();
        let extra_ignore = config_dir.join("extra.ignore");

        std::fs::write(&extra_ignore, "generated/**\n!generated/keep.md\n").unwrap();
        std::fs::write(&semgrepignore, ":include .config/extra.ignore\n").unwrap();

        let matcher = IgnoreMatcher::from_file(&semgrepignore).unwrap();
        assert!(matcher.is_ignored(&dir.path().join("generated/blocked.md")));
        assert!(!matcher.is_ignored(&dir.path().join("generated/keep.md")));
    }

    #[test]
    fn matcher_ignores_include_cycles() {
        let dir = tempdir().unwrap();
        let a = dir.path().join("a.ignore");
        let b = dir.path().join("b.ignore");

        std::fs::write(&a, ":include b.ignore\ncache/\n").unwrap();
        std::fs::write(&b, ":include a.ignore\n").unwrap();

        let matcher = IgnoreMatcher::from_file(&a).unwrap();
        assert!(matcher.is_ignored(&dir.path().join("cache/data.txt")));
    }
}
