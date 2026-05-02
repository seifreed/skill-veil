use super::condition::RuleCondition;
use super::schema::Rule;
use super::RuleError;
use crate::analyzer::SkillDocument;
use crate::findings::{ArtifactKind, EvidenceKind, Finding, MatchTarget, ThreatCategory};
use crate::patterns::try_compile;
use crate::ports::{CompiledPattern, PatternMatcher};
use std::collections::HashMap;

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
/// Contains the original rule along with pre-compiled pattern handles
/// keyed by the source pattern string from the condition tree.
///
/// # Performance contract
///
/// Patterns are compiled once at rule load time (in [`CompiledRule::compile`])
/// and reused across every document and section evaluation. Pre-fix the
/// engine recompiled each `RuleCondition::Regex { pattern }` on every call
/// because `check_regex_condition` invoked `matcher.find_matches(pattern,
/// text)` — and the `RegexPatternMatcher` trait method goes through
/// `Regex::new(pattern)` per invocation. For N documents × R rules with
/// regex conditions this was O(N·R) regex compilations per scan; on a
/// large corpus with the shipped 78+ built-in rules that dominated wall
/// time and made user-supplied alternations a DoS amplifier.
///
/// `compiled_patterns` is keyed by the literal pattern string so the
/// rule engine can look up the pre-compiled handle directly from each
/// `RuleCondition::Regex { pattern }` or `RuleCondition::SectionRegex
/// { pattern, .. }` node at match time.
pub struct CompiledRule {
    /// The original rule definition
    pub rule: Rule,
    /// Pre-compiled handles for every regex pattern referenced by the
    /// rule's condition tree. Built once in [`CompiledRule::compile`]
    /// and consulted via lookup at match time so [`PatternMatcher`]'s
    /// per-call `Regex::new` path is never on the hot path.
    compiled_patterns: HashMap<String, CompiledPattern>,
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
        _ if doc
            .path
            .parent()
            .and_then(|parent| parent.file_name())
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("prompts")) =>
        {
            ArtifactKind::PromptPackDocument
        }
        _ => ArtifactKind::ReferencedArtifact,
    }
}

impl CompiledRule {
    /// Compile a rule for matching
    ///
    /// This validates all regex patterns in the rule condition AND
    /// caches the compiled handles for reuse across every subsequent
    /// document evaluation. Returns an error if any pattern has invalid
    /// regex syntax.
    ///
    /// Compilation goes through `try_compile`, which wraps the matcher
    /// port so the rule loader never names the concrete adapter.
    pub fn compile(rule: Rule) -> Result<Self, RuleError> {
        Self::validate_value_caps(&rule.condition)?;
        let pattern_strings = Self::extract_pattern_strings(&rule.condition);
        let mut compiled_patterns = HashMap::with_capacity(pattern_strings.len());
        for pattern in pattern_strings {
            // Skip duplicates: a rule with `Any([Regex {p}, Regex {p}])`
            // would otherwise compile the same pattern twice. The first
            // compilation governs.
            if compiled_patterns.contains_key(&pattern) {
                continue;
            }
            let handle = try_compile(&pattern)?;
            compiled_patterns.insert(pattern, handle);
        }
        Ok(Self {
            rule,
            compiled_patterns,
        })
    }

    /// Recursively walk the condition tree and reject `SectionContains`
    /// nodes whose `values` list exceeds `MAX_SECTION_CONTAINS_VALUES`.
    /// Pre-cap, an external pack could declare an arbitrarily large
    /// alternation and force the matcher into pathological compile-time
    /// memory use.
    fn validate_value_caps(condition: &RuleCondition) -> Result<(), RuleError> {
        match condition {
            RuleCondition::SectionContains { values, .. }
                if values.len() > MAX_SECTION_CONTAINS_VALUES =>
            {
                return Err(RuleError::InvalidRule(format!(
                    "SectionContains has {} values; the per-rule cap is {} \
                     (split the rule or use a single Regex condition instead)",
                    values.len(),
                    MAX_SECTION_CONTAINS_VALUES
                )));
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
                // SectionContains matching uses str::contains, not regex —
                // compiling these values wastes memory and CPU at load time.
                let _ = values;
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

    /// Check if this rule matches the document.
    ///
    /// The `matcher` argument is preserved for API stability — pre-fix
    /// the engine called `matcher.find_matches(pattern, ...)` per
    /// document, which forced [`PatternMatcher::find_matches`] to
    /// recompile the pattern on every call. Compiled handles now live
    /// inside [`CompiledRule::compiled_patterns`] and the matcher is
    /// only consulted at rule load time, so this argument is unused on
    /// the hot path. Keeping it in the signature lets external rule
    /// engines that hold a custom matcher continue to work, and lets a
    /// future `Yara` or feature-flagged matcher plug back in without
    /// another API break.
    pub fn matches<M: PatternMatcher>(&self, doc: &SkillDocument, _matcher: &M) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !self.rule.enabled {
            return findings;
        }

        self.check_condition(&self.rule.condition, doc, &mut findings);
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

    fn check_regex_condition(
        &self,
        pattern: &str,
        doc: &SkillDocument,
        findings: &mut Vec<Finding>,
    ) -> bool {
        let Some(compiled) = self.compiled_patterns.get(pattern) else {
            // Unreachable on well-formed rules — `compile()` populates
            // the cache from the same condition tree we're walking. A
            // miss would only happen if the cache was bypassed by an
            // out-of-band mutation, which the API surface doesn't allow.
            tracing::warn!(
                rule_id = %self.rule.id,
                "regex pattern missing from compiled-pattern cache; this is a bug"
            );
            return false;
        };
        let matches = compiled.find_matches(&doc.raw_content);

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
                findings.push(self.create_finding(target, value.to_lowercase()));
                matched = true;
            }
        }
        matched
    }

    fn check_section_regex_condition(
        &self,
        section: &str,
        pattern: &str,
        doc: &SkillDocument,
        findings: &mut Vec<Finding>,
    ) -> bool {
        let Some(sec) = doc.get_section(section) else {
            return false;
        };

        let Some(compiled) = self.compiled_patterns.get(pattern) else {
            tracing::warn!(
                rule_id = %self.rule.id,
                "section regex pattern missing from compiled-pattern cache; this is a bug"
            );
            return false;
        };
        let matches = compiled.find_matches(&sec.content);
        let initial_count = findings.len();
        for mat in matches {
            // Convert section-relative offset to document-relative
            // line number so inline suppressions (which operate on
            // document-level line numbers) can match these findings.
            let line_number =
                calculate_line_number(&sec.content, mat.start) + sec.start_line.saturating_sub(1);
            let finding = self
                .create_finding(
                    MatchTarget::Section {
                        name: section.to_string(),
                    },
                    &mat.matched_text,
                )
                .with_line(line_number);
            findings.push(finding);
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

    fn check_any_conditions(
        &self,
        conditions: &[RuleCondition],
        doc: &SkillDocument,
        findings: &mut Vec<Finding>,
    ) -> bool {
        let mut matched = false;
        for cond in conditions {
            let mut branch_findings = Vec::new();
            if self.check_condition(cond, doc, &mut branch_findings) {
                findings.extend(branch_findings);
                matched = true;
            }
        }
        matched
    }

    fn check_all_conditions(
        &self,
        conditions: &[RuleCondition],
        doc: &SkillDocument,
        findings: &mut Vec<Finding>,
    ) -> bool {
        let mut branch_findings = Vec::new();
        for cond in conditions {
            if !self.check_condition(cond, doc, &mut branch_findings) {
                return false;
            }
        }

        findings.extend(branch_findings);
        true
    }

    fn check_condition(
        &self,
        condition: &RuleCondition,
        doc: &SkillDocument,
        findings: &mut Vec<Finding>,
    ) -> bool {
        match condition {
            RuleCondition::Regex { pattern } => self.check_regex_condition(pattern, doc, findings),
            RuleCondition::SectionContains { section, values } => {
                self.check_section_condition(section, values, doc, findings)
            }
            RuleCondition::SectionRegex { section, pattern } => {
                self.check_section_regex_condition(section, pattern, doc, findings)
            }
            RuleCondition::ArtifactKind { kinds } => {
                self.check_artifact_kind_condition(kinds, doc, findings)
            }
            RuleCondition::CodeLanguage { languages } => {
                self.check_code_language_condition(languages, doc, findings)
            }
            RuleCondition::Any(conditions) => self.check_any_conditions(conditions, doc, findings),
            RuleCondition::All(conditions) => self.check_all_conditions(conditions, doc, findings),
            #[cfg(feature = "yara")]
            RuleCondition::Yara { .. } => {
                // YARA matching is handled by the yara_engine module
                false
            }
        }
    }
}
