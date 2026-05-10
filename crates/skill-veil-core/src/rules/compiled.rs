use super::condition::RuleCondition;
use super::schema::Rule;
use super::RuleError;
use crate::analyzer::SkillDocument;
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, SignalClass,
    ThreatCategory,
};
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
        self.create_finding_with_doc(target, match_value, None)
    }
}

/// `true` if `match_text` appears as a substring of any fenced
/// code-block body within the document. Used by
/// `requires_code_artifact` rules to distinguish a real code-anchored
/// match from a prose-only match that should be downgraded.
///
/// The check is intentionally a literal substring search (no regex,
/// no case-folding) — the input is the exact text returned by the
/// regex matcher. Case-insensitive rule patterns produce a literal
/// match in whatever case they found it in the source, so the same
/// case appears in `code_blocks[].code` if the match was actually a
/// code-block fire.
fn match_appears_in_code_block(doc: &SkillDocument, match_text: &str) -> bool {
    if match_text.is_empty() {
        return false;
    }
    doc.sections
        .iter()
        .flat_map(|s| s.code_blocks.iter())
        .any(|block| block.code.contains(match_text))
}

/// Substring markers (case-insensitive) that indicate the document
/// declares an explicit human-in-the-loop confirmation gate. When
/// any of these phrases appears in `doc.raw_content`, rules with
/// `downgrade_when_confirmation_gate: true` emit downgraded findings
/// — the gate is precisely the safety control the rule was designed
/// to require.
///
/// Markers come from inspecting the LLM_FP samples produced by the
/// cross-LLM triage (`okx-trading`, `franchise-evaluation-coach` and
/// similar workflows). Add a new marker only after observing it in
/// at least one real benign skill that currently produces a FP.
const CONFIRMATION_GATE_MARKERS: &[&str] = &[
    "confirmation_token",
    "confirmation token",
    "human-in-the-loop",
    "human in the loop",
    "explicit yes",
    "user types yes",
    "user must reply yes",
    "user must reply",
    "two-step gate",
    "two step gate",
    "explicit confirmation",
    "explicitly confirm",
    "propose → user",
    "propose -> user",
    "ask the user to reply",
    "wait for the user's reply",
    "do not proceed otherwise",
    "yes <id>",
    "yes <token>",
];

/// Substring markers (case-insensitive) that indicate the document
/// is itself an educational / detection / anti-pattern catalogue
/// (security scanners, pattern-matching guides). When any appears,
/// rules with `downgrade_when_documentation_context: true` emit
/// downgraded findings.
const DOCUMENTATION_CONTEXT_MARKERS: &[&str] = &[
    "## what it checks",
    "## anti-patterns",
    "## anti patterns",
    "### anti-patterns",
    "### anti patterns",
    "## detection patterns",
    "## blocked patterns",
    "this skill detects",
    "this skill checks",
    "examples of bad code",
    "patterns we block",
    "## patterns",
    "## examples (",
    "(❌ bad)",
    "(✅ good)",
    "// anti-pattern",
    "# anti-pattern",
];

/// `true` if any [`CONFIRMATION_GATE_MARKERS`] substring (case-
/// insensitive) appears in the document's raw markdown body.
fn doc_has_confirmation_gate(doc: &SkillDocument) -> bool {
    let lower = doc.raw_content.to_ascii_lowercase();
    CONFIRMATION_GATE_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

/// `true` if any [`DOCUMENTATION_CONTEXT_MARKERS`] substring (case-
/// insensitive) appears in the document's raw markdown body.
fn doc_has_documentation_context(doc: &SkillDocument) -> bool {
    let lower = doc.raw_content.to_ascii_lowercase();
    DOCUMENTATION_CONTEXT_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

// `impl CompiledRule { ... }` continues from here — the helper above
// is module-level so other compiled-rule helpers can use it without
// indirection.
impl CompiledRule {
    /// Builds the finding while optionally consulting the parent
    /// `SkillDocument` for `requires_code_artifact` rules.
    ///
    /// When `doc` is `Some` AND the rule has `requires_code_artifact:
    /// true` AND the `MatchTarget` is `Document` or `Section`, this
    /// helper checks whether the matched text appears in any
    /// fenced-code-block content within the document. If it does
    /// NOT, the finding is downgraded:
    /// - `RecommendedAction::Block` → `RequireApproval`
    /// - `SignalClass::MaliciousBehavior` → `ReviewSignal`
    /// - `reason` gets a "(downgraded: prose-only match)" suffix
    ///
    /// Matches in `CodeBlock` / `ReferencedFile` targets bypass the
    /// downgrade entirely — those targets are already "in code" by
    /// construction. The check is a substring search rather than an
    /// offset map: a regex match returns the literal matched text;
    /// if that text appears in any of the document's code blocks the
    /// match is plausibly code-anchored. The corner case where the
    /// same string appears in BOTH prose and code yields full
    /// strength — the safe direction.
    fn create_finding_with_doc(
        &self,
        target: MatchTarget,
        match_value: impl Into<String>,
        doc: Option<&SkillDocument>,
    ) -> Finding {
        let artifact_kind = match &target {
            MatchTarget::Document | MatchTarget::Section { .. } => ArtifactKind::SkillDocument,
            MatchTarget::CodeBlock { .. } => ArtifactKind::CodeSnippet,
            MatchTarget::ReferencedFile { .. } => ArtifactKind::ReferencedArtifact,
        };
        let match_value_str: String = match_value.into();

        // Compute the three downgrade triggers that may apply to
        // this finding. Each is gated on its own opt-in field on the
        // rule so an author cannot accidentally trip a downgrade by
        // labelling unrelated content with the markers.
        let prose_only_downgrade = self.rule.requires_code_artifact
            && matches!(&target, MatchTarget::Document | MatchTarget::Section { .. })
            && doc
                .map(|d| !match_appears_in_code_block(d, &match_value_str))
                .unwrap_or(false);
        let confirmation_gate_downgrade = self.rule.downgrade_when_confirmation_gate
            && doc.map(doc_has_confirmation_gate).unwrap_or(false);
        let documentation_context_downgrade = self.rule.downgrade_when_documentation_context
            && doc.map(doc_has_documentation_context).unwrap_or(false);

        let any_downgrade =
            prose_only_downgrade || confirmation_gate_downgrade || documentation_context_downgrade;

        let mut action = self.rule.action;
        let mut signal_class_override: Option<SignalClass> = None;
        let mut reason = self.rule.reason.clone();
        if any_downgrade {
            action = match action {
                RecommendedAction::Block => RecommendedAction::RequireApproval,
                other => other,
            };
            signal_class_override = Some(SignalClass::ReviewSignal);
            let mut notes: Vec<&str> = Vec::new();
            if prose_only_downgrade {
                notes.push("prose-only match");
            }
            if confirmation_gate_downgrade {
                notes.push("confirmation-gate present in document");
            }
            if documentation_context_downgrade {
                notes.push("document is an educational / detection catalogue");
            }
            reason.push_str(" (downgraded: ");
            reason.push_str(&notes.join("; "));
            reason.push(')');
        }

        let mut builder = Finding::builder(&self.rule.id, self.rule.category)
            .severity(self.rule.severity)
            .confidence(self.rule.confidence)
            .action(action)
            .evidence_kind(self.evidence_kind())
            .artifact(artifact_kind, None)
            .matched_on(target)
            .match_value(match_value_str)
            .reason(reason);
        if let Some(sc) = signal_class_override {
            builder = builder.signal_class(sc);
        }
        builder.build()
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
                .create_finding_with_doc(MatchTarget::Document, &mat.matched_text, Some(doc))
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

        // Build a mapping from lowercased character index to original character
        // index. Case-folding can expand characters (e.g. İ → i̇, ß → ss), so a
        // position in the lowercased string does not correspond 1-to-1 with the
        // original. Without this mapping, `char_offset` computed from
        // `content_lower` would point to the wrong position in `sec.content`.
        let mut lower_to_original: Vec<usize> = Vec::new();
        for (orig_idx, ch) in sec.content.chars().enumerate() {
            for _ in ch.to_lowercase() {
                lower_to_original.push(orig_idx);
            }
        }
        // Sentinel: one-past-the-end original char index, used when the match
        // extends to the end of the lowercased content.
        lower_to_original.push(sec.content.chars().count());

        for value in values {
            if value.is_empty() {
                continue;
            }
            let value_lower = value.to_lowercase();
            // Find ALL occurrences, not just the first. A malicious string
            // appearing multiple times in a section should produce multiple
            // findings — finding only the first undercounts risk.
            let mut search_from = 0;
            while let Some(pos_lower) = content_lower[search_from..].find(&value_lower) {
                // Map the byte offset in `content_lower` to the corresponding
                // character range in the original mixed-case content via the
                // lower_to_original index built above.
                let lower_char_start = content_lower[..search_from + pos_lower].chars().count();
                let lower_char_end = lower_char_start + value_lower.chars().count();
                let orig_start = lower_to_original[lower_char_start];
                let orig_end = lower_to_original[lower_char_end];
                let original_text: String = sec
                    .content
                    .chars()
                    .skip(orig_start)
                    .take(orig_end - orig_start)
                    .collect();
                // Convert section-relative char offset to document-relative
                // line number so inline suppressions (which key on
                // document-level line numbers) can match these findings.
                let orig_byte_offset = sec
                    .content
                    .char_indices()
                    .nth(orig_start)
                    .map_or(sec.content.len(), |(idx, _)| idx);
                let line_number = calculate_line_number(&sec.content, orig_byte_offset)
                    + sec.start_line.saturating_sub(1);
                let target = MatchTarget::Section {
                    name: section.to_string(),
                };
                findings.push(
                    self.create_finding_with_doc(target, &original_text, Some(doc))
                        .with_line(line_number),
                );
                matched = true;
                // Advance past this match to find subsequent occurrences.
                // Use character count, not byte length, to advance because
                // case-folding can change byte length (e.g. İ → i̇: 2 bytes
                // become 3). Walking by chars and converting back to a byte
                // offset in `content_lower` avoids skipping or re-matching
                // when the lowercase form differs in byte width from the
                // original.
                let match_end_bytes = search_from + pos_lower + value_lower.len();
                let advance_chars = content_lower[..match_end_bytes].chars().count();
                search_from = content_lower
                    .char_indices()
                    .nth(advance_chars)
                    .map_or(match_end_bytes, |(idx, _)| idx);
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
                .create_finding_with_doc(
                    MatchTarget::Section {
                        name: section.to_string(),
                    },
                    &mat.matched_text,
                    Some(doc),
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
