use super::condition::RuleCondition;
use super::schema::Rule;
use super::RuleError;
use crate::analyzer::SkillDocument;
use crate::findings::{ArtifactKind, EvidenceKind, Finding, MatchTarget, ThreatCategory};
use crate::ports::PatternMatcher;

/// Hard cap on the number of literal values a single `SectionContains`
/// condition may declare. Each value is wrapped in `regex::escape` and
/// or-joined into the matcher's pattern set; without a cap, a malicious
/// pack could declare 100k+ values and force the matcher into worst-case
/// memory and compile-time territory. 200 is well above any legitimate
/// rule (the largest built-in `SectionContains` has fewer than 30
/// values) while bounding the worst case.
const MAX_SECTION_CONTAINS_VALUES: usize = 200;

/// Compiled version of a rule for efficient matching
///
/// Contains the original rule along with pre-extracted pattern strings
/// for efficient matching against documents.
pub struct CompiledRule {
    /// The original rule definition
    pub rule: Rule,
    /// Pattern strings extracted from the rule condition
    pub pattern_strings: Vec<String>,
}

fn calculate_line_number(content: &str, offset: usize) -> usize {
    content[..offset].chars().filter(|c| *c == '\n').count() + 1
}

pub(super) fn artifact_kind_for_document(doc: &SkillDocument) -> ArtifactKind {
    let file_name = doc
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_ascii_lowercase);
    match file_name.as_deref() {
        Some("mcp.json" | "mcp.yaml" | "mcp.yml") => ArtifactKind::McpServerManifest,
        Some(
            "package.json"
            | "requirements.txt"
            | "pyproject.toml"
            | "cargo.toml"
            | "dockerfile"
            | "docker-compose.yml"
            | "docker-compose.yaml"
            | "makefile"
            | ".npmrc"
            | "pip.conf",
        ) => ArtifactKind::PackageManifest,
        Some(
            "package-lock.json"
            | "cargo.lock"
            | "poetry.lock"
            | "uv.lock"
            | "pipfile.lock"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "npm-shrinkwrap.json",
        ) => ArtifactKind::Lockfile,
        Some("agents.md" | "claude.md" | "system.md" | "persona.md" | "soul.md") => {
            ArtifactKind::AgentInstruction
        }
        Some(name) if name.ends_with(".prompt.md") => ArtifactKind::PromptPackDocument,
        Some("skill.md") => ArtifactKind::SkillDocument,
        Some(name) if name.ends_with(".skill.md") => ArtifactKind::SkillDocument,
        _ => ArtifactKind::ReferencedArtifact,
    }
}

impl CompiledRule {
    /// Compile a rule for matching
    ///
    /// This validates all regex patterns in the rule condition and returns an error
    /// if any pattern has invalid regex syntax.
    pub fn compile(rule: Rule) -> Result<Self, RuleError> {
        Self::validate_value_caps(&rule.condition)?;
        let pattern_strings = Self::extract_pattern_strings(&rule.condition);
        // Validate all regex patterns at compile time to catch syntax errors early
        for pattern in &pattern_strings {
            if let Err(e) = regex::Regex::new(pattern) {
                return Err(RuleError::RegexError(e));
            }
        }
        Ok(Self {
            rule,
            pattern_strings,
        })
    }

    /// Recursively walk the condition tree and reject `SectionContains`
    /// nodes whose `values` list exceeds `MAX_SECTION_CONTAINS_VALUES`.
    /// Pre-cap, an external pack could declare an arbitrarily large
    /// alternation and force the matcher into pathological compile-time
    /// memory use.
    fn validate_value_caps(condition: &RuleCondition) -> Result<(), RuleError> {
        match condition {
            RuleCondition::SectionContains { values, .. } => {
                if values.len() > MAX_SECTION_CONTAINS_VALUES {
                    return Err(RuleError::InvalidRule(format!(
                        "SectionContains has {} values; the per-rule cap is {} \
                         (split the rule or use a single Regex condition instead)",
                        values.len(),
                        MAX_SECTION_CONTAINS_VALUES
                    )));
                }
            }
            RuleCondition::Any(conditions) | RuleCondition::All(conditions) => {
                for cond in conditions {
                    Self::validate_value_caps(cond)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn extract_pattern_strings(condition: &RuleCondition) -> Vec<String> {
        let mut patterns = Vec::new();

        match condition {
            RuleCondition::Regex { pattern } => {
                patterns.push(pattern.clone());
            }
            RuleCondition::SectionContains { values, .. } => {
                for value in values {
                    // Escape the value for literal matching
                    patterns.push(regex::escape(value));
                }
            }
            RuleCondition::SectionRegex { pattern, .. } => {
                patterns.push(pattern.clone());
            }
            RuleCondition::ArtifactKind { .. } => {}
            RuleCondition::Any(conditions) | RuleCondition::All(conditions) => {
                for cond in conditions {
                    patterns.extend(Self::extract_pattern_strings(cond));
                }
            }
            RuleCondition::CodeLanguage { .. } => {
                // No regex patterns needed
            }
            #[cfg(feature = "yara")]
            RuleCondition::Yara { .. } => {
                // YARA rules are handled separately
            }
        }

        patterns
    }

    /// Check if this rule matches the document using the provided matcher
    pub fn matches<M: PatternMatcher>(&self, doc: &SkillDocument, matcher: &M) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !self.rule.enabled {
            return findings;
        }

        self.check_condition(&self.rule.condition, doc, matcher, &mut findings);
        findings
    }

    fn create_finding(&self, target: MatchTarget, match_value: impl Into<String>) -> Finding {
        let artifact_kind = match &target {
            MatchTarget::Document | MatchTarget::Section { .. } => ArtifactKind::SkillDocument,
            MatchTarget::CodeBlock { .. } => ArtifactKind::CodeSnippet,
            MatchTarget::ReferencedFile { .. } => ArtifactKind::ReferencedArtifact,
        };

        Finding::builder(&self.rule.id, self.rule.category)
            .severity(self.rule.severity)
            .confidence(self.rule.confidence)
            .action(self.rule.action)
            .evidence_kind(self.evidence_kind())
            .artifact(artifact_kind, None)
            .matched_on(target)
            .match_value(match_value)
            .reason(&self.rule.reason)
            .build()
    }

    fn evidence_kind(&self) -> EvidenceKind {
        if self.rule.tags.iter().any(|tag| {
            matches!(
                tag.as_str(),
                "ioc" | "publisher" | "malicious_domain" | "c2"
            )
        }) {
            return EvidenceKind::Ioc;
        }

        if matches!(
            self.rule.category,
            ThreatCategory::PersuasiveLanguage | ThreatCategory::SocialManipulation
        ) || self
            .rule
            .tags
            .iter()
            .any(|tag| matches!(tag.as_str(), "jailbreak" | "manipulation" | "semantic"))
        {
            return EvidenceKind::Intent;
        }

        if matches!(
            self.rule.category,
            ThreatCategory::ScopeCreep
                | ThreatCategory::PersistentPromptTampering
                | ThreatCategory::ToolAbuse
                | ThreatCategory::AutonomyEscalation
        ) || self.rule.tags.iter().any(|tag| {
            matches!(
                tag.as_str(),
                "persistence" | "filesystem" | "context" | "tool_abuse" | "autonomy"
            )
        }) {
            return EvidenceKind::Context;
        }

        EvidenceKind::Behavior
    }

    fn check_regex_condition<M: PatternMatcher>(
        &self,
        pattern: &str,
        doc: &SkillDocument,
        matcher: &M,
        findings: &mut Vec<Finding>,
    ) -> bool {
        let matches = matcher.find_matches(pattern, &doc.raw_content);

        let initial_count = findings.len();
        for mat in matches {
            let line_number = calculate_line_number(&doc.raw_content, mat.start);
            let finding = self
                .create_finding(MatchTarget::Document, &mat.matched_text)
                .with_line(line_number);
            findings.push(finding);
        }

        findings.len() > initial_count
    }

    fn check_section_condition(
        &self,
        section: &str,
        values: &[String],
        doc: &SkillDocument,
        findings: &mut Vec<Finding>,
    ) -> bool {
        let Some(sec) = doc.get_section(section) else {
            return false;
        };

        let mut matched = false;
        let content_lower = sec.content.to_lowercase();
        for value in values {
            if value.is_empty() {
                continue;
            }
            if content_lower.contains(&value.to_lowercase()) {
                let target = MatchTarget::Section {
                    name: section.to_string(),
                };
                findings.push(self.create_finding(target, value));
                matched = true;
            }
        }
        matched
    }

    fn check_section_regex_condition<M: PatternMatcher>(
        &self,
        section: &str,
        pattern: &str,
        doc: &SkillDocument,
        matcher: &M,
        findings: &mut Vec<Finding>,
    ) -> bool {
        let Some(sec) = doc.get_section(section) else {
            return false;
        };

        let matches = matcher.find_matches(pattern, &sec.content);
        let initial_count = findings.len();
        for mat in matches {
            findings.push(self.create_finding(
                MatchTarget::Section {
                    name: section.to_string(),
                },
                &mat.matched_text,
            ));
        }
        findings.len() > initial_count
    }

    fn check_artifact_kind_condition(
        &self,
        kinds: &[crate::findings::ArtifactKind],
        doc: &SkillDocument,
        findings: &mut Vec<Finding>,
    ) -> bool {
        let artifact_kind = artifact_kind_for_document(doc);
        if kinds.contains(&artifact_kind) {
            findings.push(self.create_finding(
                MatchTarget::Document,
                format!("artifact_kind={artifact_kind}"),
            ));
            return true;
        }
        false
    }

    fn check_code_language_condition(
        &self,
        languages: &[String],
        doc: &SkillDocument,
        findings: &mut Vec<Finding>,
    ) -> bool {
        let mut matched = false;
        for lang in languages {
            if doc.has_code_language(lang) {
                let target = MatchTarget::CodeBlock {
                    language: Some(lang.clone()),
                };
                let match_value = format!("Code block with language: {}", lang);
                findings.push(self.create_finding(target, match_value));
                matched = true;
            }
        }
        matched
    }

    fn check_any_conditions<M: PatternMatcher>(
        &self,
        conditions: &[RuleCondition],
        doc: &SkillDocument,
        matcher: &M,
        findings: &mut Vec<Finding>,
    ) -> bool {
        let mut matched = false;
        for cond in conditions {
            let mut branch_findings = Vec::new();
            if self.check_condition(cond, doc, matcher, &mut branch_findings) {
                findings.extend(branch_findings);
                matched = true;
            }
        }
        matched
    }

    fn check_all_conditions<M: PatternMatcher>(
        &self,
        conditions: &[RuleCondition],
        doc: &SkillDocument,
        matcher: &M,
        findings: &mut Vec<Finding>,
    ) -> bool {
        let mut branch_findings = Vec::new();
        for cond in conditions {
            if !self.check_condition(cond, doc, matcher, &mut branch_findings) {
                return false;
            }
        }

        findings.extend(branch_findings);
        true
    }

    fn check_condition<M: PatternMatcher>(
        &self,
        condition: &RuleCondition,
        doc: &SkillDocument,
        matcher: &M,
        findings: &mut Vec<Finding>,
    ) -> bool {
        match condition {
            RuleCondition::Regex { pattern } => {
                self.check_regex_condition(pattern, doc, matcher, findings)
            }
            RuleCondition::SectionContains { section, values } => {
                self.check_section_condition(section, values, doc, findings)
            }
            RuleCondition::SectionRegex { section, pattern } => {
                self.check_section_regex_condition(section, pattern, doc, matcher, findings)
            }
            RuleCondition::ArtifactKind { kinds } => {
                self.check_artifact_kind_condition(kinds, doc, findings)
            }
            RuleCondition::CodeLanguage { languages } => {
                self.check_code_language_condition(languages, doc, findings)
            }
            RuleCondition::Any(conditions) => {
                self.check_any_conditions(conditions, doc, matcher, findings)
            }
            RuleCondition::All(conditions) => {
                self.check_all_conditions(conditions, doc, matcher, findings)
            }
            #[cfg(feature = "yara")]
            RuleCondition::Yara { .. } => {
                // YARA matching is handled by the yara_engine module
                false
            }
        }
    }
}
