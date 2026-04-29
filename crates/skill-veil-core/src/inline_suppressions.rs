use crate::findings::{Finding, SuppressionRecord};
use crate::lazy_pattern;
use crate::policy::fingerprint::paths_match;
use crate::ports::Captures;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

lazy_pattern!(
    STANDALONE_SUPPRESSION_REGEX,
    r#"(?i)^\s*(?:(?:<!--|#|//|/\*+|\*|;|--)\s*(?:skill-veil:)?|skill-veil:)(ignore-next-line|ignore|nosemgrep-next-line|nosemgrep|nosem-next-line|nosem)\b(?:[:\s]+([A-Za-z0-9*_,.\-]+))?"#
);

/// Maximum characters retained from the `reason=` / `because=` payload
/// of an inline suppression directive. The captured reason flows into
/// `SuppressionRecord.reason`, then into JSON / SARIF output, then into
/// every downstream consumer that re-serializes findings. Pre-cap, a
/// malformed comment with megabytes of text after `reason=` would
/// allocate a `String` that size and propagate it through every
/// serializer — a single bad skill could exhaust memory or balloon the
/// report file. The regex caps the capture at this length and the
/// `chars().take(...)` post-truncate in `add_suppressions_from_capture`
/// guards the contract even if the regex is later relaxed.
const MAX_SUPPRESSION_REASON_CHARS: usize = 500;

lazy_pattern!(
    INLINE_SUPPRESSION_REGEX,
    r#"(?i)(?:<!--|#|//|/\*+|;|--)\s*(?:skill-veil:)?(ignore-next-line|ignore|nosemgrep-next-line|nosemgrep|nosem-next-line|nosem)\b(?:[:\s]+([A-Za-z0-9*_,.\-]+))?(?:\s+(?:because|reason)[:=]\s*([^#]{0,500}))?"#
);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineSuppression {
    pub path: String,
    pub rule_id: String,
    pub applies_to_line: Option<usize>,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

fn collect_comment_suppressions(path: &Path, content: &str) -> Vec<InlineSuppression> {
    let artifact_path = path.display().to_string();

    let mut suppressions = Vec::new();
    let lines: Vec<_> = content.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        let line_number = index + 1;
        if let Some(capture) = STANDALONE_SUPPRESSION_REGEX
            .captures_iter(line)
            .into_iter()
            .next()
        {
            add_suppressions_from_capture(
                &mut suppressions,
                &artifact_path,
                line_number,
                true,
                next_significant_line(&lines, index),
                &capture,
            );
            continue;
        }

        let next_line = next_significant_line(&lines, index);
        for capture in INLINE_SUPPRESSION_REGEX.captures_iter(line) {
            add_suppressions_from_capture(
                &mut suppressions,
                &artifact_path,
                line_number,
                false,
                next_line,
                &capture,
            );
        }
    }

    suppressions
}

fn add_suppressions_from_capture(
    suppressions: &mut Vec<InlineSuppression>,
    artifact_path: &str,
    line_number: usize,
    standalone: bool,
    next_line_number: Option<usize>,
    capture: &Captures,
) {
    let Some(kind) = capture.get(1).map(|m| m.matched_text.to_ascii_lowercase()) else {
        return;
    };
    let rule_list = capture
        .get(2)
        .map(|m| m.matched_text.as_str())
        .unwrap_or("*");
    // Defensive truncation in addition to the regex `{0,500}` cap. The
    // doc-comment on `MAX_SUPPRESSION_REASON_CHARS` explains the contract;
    // belt-and-braces here ensures the limit holds even if the regex is
    // later relaxed during a routine refactor.
    let reason = capture.get(3).map(|m| {
        m.matched_text
            .trim()
            .chars()
            .take(MAX_SUPPRESSION_REASON_CHARS)
            .collect::<String>()
    });
    // Standalone comments (on their own line) with "ignore" target the next significant
    // line — a standalone `<!-- ignore RULE -->` acts like `ignore-next-line`.
    // Standalone nosem/nosemgrep on their own line are no-ops (matching semgrep semantics:
    // a standalone `# nosem` has no effect since it can't suppress the comment itself).
    // Only an inline `ignore` (appended to a content line) is file-wide.
    let applies_to_line = if kind.ends_with("next-line") {
        match next_line_number {
            Some(line) => Some(line),
            None => return, // nothing to suppress at EOF
        }
    } else if standalone && kind == "ignore" {
        // Standalone ignore: target next significant line if one exists,
        // otherwise treat as no-op (nothing to target at EOF).
        match next_line_number {
            Some(line) => Some(line),
            None => return,
        }
    } else if kind == "ignore" {
        None // inline file-wide suppression
    } else if standalone {
        // Standalone nosem/nosemgrep on its own line is a no-op: it cannot
        // suppress the comment line itself, matching standard semgrep semantics.
        // Users who intend file-wide suppression should use `ignore` instead.
        return;
    } else {
        // nosem / nosemgrep inline: suppress on the current line
        Some(line_number)
    };

    for rule_id in rule_list
        .split(',')
        .map(str::trim)
        .filter(|rule_id| !rule_id.is_empty())
    {
        suppressions.push(InlineSuppression {
            path: artifact_path.to_string(),
            rule_id: rule_id.to_string(),
            applies_to_line,
            kind: kind.clone(),
            reason: reason.clone(),
            expires_at: None,
        });
    }
}

fn next_significant_line(lines: &[&str], index: usize) -> Option<usize> {
    lines
        .iter()
        .enumerate()
        .skip(index + 1)
        .find_map(|(line_index, line)| {
            let trimmed = line.trim();
            (!trimmed.is_empty() && !trimmed.starts_with("```") && !trimmed.starts_with("<!--"))
                .then_some(line_index + 1)
        })
}

fn collect_json_suppressions(path: &Path, content: &str) -> Vec<InlineSuppression> {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(content) else {
        return Vec::new();
    };

    let Some(entries) = json
        .get("x-skill-veil-ignore")
        .or_else(|| json.get("skill-veil-ignore"))
    else {
        return Vec::new();
    };

    let artifact_path = path.display().to_string();

    // Single string: "x-skill-veil-ignore": "MY_RULE"
    if let Some(rule_id) = entries.as_str() {
        return vec![InlineSuppression {
            path: artifact_path,
            rule_id: rule_id.to_string(),
            applies_to_line: None,
            kind: "ignore".to_string(),
            reason: None,
            expires_at: None,
        }];
    }

    // Single object: "x-skill-veil-ignore": {"rule_id": "MY_RULE", ...}
    if let Some(object) = entries.as_object() {
        if let Some(suppression) = parse_json_suppression_object(object, &artifact_path) {
            return vec![suppression];
        }
        return Vec::new();
    }

    // Array of strings/objects (existing behavior)
    if let Some(rule_ids) = entries.as_array() {
        return rule_ids
            .iter()
            .filter_map(|entry| {
                if let Some(rule_id) = entry.as_str() {
                    return Some(InlineSuppression {
                        path: artifact_path.clone(),
                        rule_id: rule_id.to_string(),
                        applies_to_line: None,
                        kind: "ignore".to_string(),
                        reason: None,
                        expires_at: None,
                    });
                }
                parse_json_suppression_object(entry.as_object()?, &artifact_path)
            })
            .collect();
    }

    Vec::new()
}

fn parse_json_suppression_object(
    object: &serde_json::Map<String, serde_json::Value>,
    artifact_path: &str,
) -> Option<InlineSuppression> {
    let rule_id = object.get("rule_id")?.as_str()?.to_string();
    let reason = object
        .get("reason")
        .and_then(|value| value.as_str())
        .map(ToString::to_string);
    let expires_at = object
        .get("expires_at")
        .and_then(|value| value.as_str())
        .and_then(|value| value.parse::<DateTime<Utc>>().ok());
    Some(InlineSuppression {
        path: artifact_path.to_string(),
        rule_id,
        applies_to_line: None,
        kind: "ignore".to_string(),
        reason,
        expires_at,
    })
}

pub(crate) fn collect_inline_suppressions(sources: &[(&Path, &str)]) -> Vec<InlineSuppression> {
    let mut suppressions = Vec::new();
    for &(path, content) in sources {
        suppressions.extend(collect_comment_suppressions(path, content));
        suppressions.extend(collect_json_suppressions(path, content));
    }
    suppressions
}

pub(crate) fn apply_inline_suppressions(
    findings: Vec<Finding>,
    suppressions: &[InlineSuppression],
    primary_path: Option<&str>,
) -> (Vec<Finding>, Vec<Finding>) {
    if suppressions.is_empty() {
        return (findings, Vec::new());
    }

    let now = Utc::now();
    let mut active: Vec<Finding> = Vec::new();
    let mut suppressed: Vec<Finding> = Vec::new();

    for finding in findings {
        let matched = suppressions.iter().find(|suppression| {
            if suppression
                .expires_at
                .is_some_and(|expires_at| expires_at < now)
            {
                return false;
            }
            let path_matches = if suppression.applies_to_line.is_none() {
                // File-wide suppression: only match findings that explicitly
                // belong to this file. Do NOT fall through to primary_path,
                // which would let a suppression in a referenced artifact
                // silence unrelated findings on the primary document.
                // NOTE: path-less findings (artifact_path == None) are
                // intentionally excluded here — they cannot be attributed
                // to a specific file, so file-wide suppressions do not
                // apply to them. Use line-specific suppressions instead.
                finding
                    .artifact_path
                    .as_ref()
                    .is_some_and(|ap| paths_match(ap, &suppression.path))
            } else {
                // Line-specific: allow primary_path fallback for path-less findings
                finding
                    .artifact_path
                    .as_ref()
                    .is_some_and(|ap| paths_match(ap, &suppression.path))
                    || (finding.artifact_path.is_none()
                        && primary_path.is_some_and(|pp| paths_match(pp, &suppression.path)))
            };
            // Rule IDs are UPPERCASE by convention (e.g. `SKILL_REMOTE_EXEC`).
            // We accept case-insensitive match in the user-facing directive
            // so `# skill-veil: ignore[skill_remote_exec]` works as well as
            // the canonical uppercase form users would copy from output.
            let rule_matches = suppression.rule_id == "*"
                || suppression.rule_id.eq_ignore_ascii_case(&finding.rule_id);
            // Line-specific suppressions (ignore-next-line, nosem) only match
            // findings that have a concrete line_number. Taint and artifact-graph
            // findings lack line context, so they can only be suppressed by
            // file-wide directives (applies_to_line == None). This is intentional:
            // a line-specific comment should not silence cross-artifact signals.
            let line_matches = suppression.applies_to_line.is_none_or(|line| {
                finding
                    .line_number
                    .is_some_and(|finding_line| finding_line == line)
            });

            path_matches && rule_matches && line_matches
        });

        if let Some(sup) = matched {
            let mut tagged = finding;
            tagged.suppression = Some(SuppressionRecord {
                kind: sup.kind.clone(),
                rule_id: sup.rule_id.clone(),
                reason: sup.reason.clone(),
            });
            suppressed.push(tagged);
        } else {
            active.push(finding);
        }
    }

    (active, suppressed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{
        ArtifactKind, ArtifactScope, EvidenceKind, MatchTarget, RecommendedAction, Severity,
        SignalClass, ThreatCategory,
    };

    fn make_finding(rule_id: &str, path: &str) -> Finding {
        Finding::builder(rule_id, ThreatCategory::DataExfiltration)
            .severity(Severity::High)
            .action(RecommendedAction::Block)
            .evidence_kind(EvidenceKind::Behavior)
            .signal_class(SignalClass::MaliciousBehavior)
            .artifact_scope(ArtifactScope::AgentEntrypoint)
            .artifact(ArtifactKind::SkillDocument, Some(path.to_string()))
            .matched_on(MatchTarget::Document)
            .reason("test")
            .match_value("x")
            .build()
    }

    #[test]
    fn inline_suppression_rule_id_is_case_insensitive() {
        // User writes directive in lowercase; finding id is canonical UPPERCASE.
        let suppression = InlineSuppression {
            path: "/tmp/skill.md".to_string(),
            rule_id: "skill_remote_exec".to_string(),
            applies_to_line: None,
            kind: "ignore".to_string(),
            reason: None,
            expires_at: None,
        };
        let finding = make_finding("SKILL_REMOTE_EXEC", "/tmp/skill.md");
        let (active, suppressed) =
            apply_inline_suppressions(vec![finding], &[suppression], Some("/tmp/skill.md"));
        assert!(active.is_empty(), "finding should be suppressed");
        assert_eq!(suppressed.len(), 1);
    }

    #[test]
    fn inline_suppression_wildcard_still_matches() {
        let suppression = InlineSuppression {
            path: "/tmp/skill.md".to_string(),
            rule_id: "*".to_string(),
            applies_to_line: None,
            kind: "ignore".to_string(),
            reason: None,
            expires_at: None,
        };
        let finding = make_finding("ANY_RULE", "/tmp/skill.md");
        let (active, suppressed) =
            apply_inline_suppressions(vec![finding], &[suppression], Some("/tmp/skill.md"));
        assert!(active.is_empty());
        assert_eq!(suppressed.len(), 1);
    }

    /// Contract: a suppression directive whose `reason=` payload is
    /// arbitrarily long MUST be capped at `MAX_SUPPRESSION_REASON_CHARS`
    /// so a single malformed comment cannot exhaust memory or balloon
    /// downstream JSON / SARIF reports. Regression for the round-5
    /// audit's Bug 2.2 — the pre-fix regex used `[^#]+` (unbounded) and
    /// the captured string flowed verbatim into `SuppressionRecord.reason`.
    #[test]
    fn inline_suppression_reason_is_capped_at_max_chars() {
        let path = std::path::PathBuf::from("/tmp/skill.md");
        let huge = "A".repeat(MAX_SUPPRESSION_REASON_CHARS * 20);
        // Use the canonical inline form: comment marker, directive, rule
        // list, `reason=` payload. `MY_RULE` matches the rule_list class
        // `[A-Za-z0-9*_,.\-]+`; brackets like `[RULE]` are not part of
        // that class and would not capture, so we keep the form simple.
        let content = format!("payload # ignore MY_RULE reason={huge}\n");
        let suppressions = collect_comment_suppressions(&path, &content);
        assert!(
            !suppressions.is_empty(),
            "directive must parse; check that the regex still recognizes \
             the canonical `# ignore RULE reason=...` form"
        );
        let reason = suppressions[0].reason.as_deref().expect("reason captured");
        assert!(
            reason.chars().count() <= MAX_SUPPRESSION_REASON_CHARS,
            "reason MUST be capped at {} chars; got {}",
            MAX_SUPPRESSION_REASON_CHARS,
            reason.chars().count()
        );
    }

    #[test]
    fn inline_suppression_unrelated_rule_id_does_not_match() {
        let suppression = InlineSuppression {
            path: "/tmp/skill.md".to_string(),
            rule_id: "OTHER_RULE".to_string(),
            applies_to_line: None,
            kind: "ignore".to_string(),
            reason: None,
            expires_at: None,
        };
        let finding = make_finding("SKILL_REMOTE_EXEC", "/tmp/skill.md");
        let (active, suppressed) =
            apply_inline_suppressions(vec![finding], &[suppression], Some("/tmp/skill.md"));
        assert_eq!(active.len(), 1);
        assert!(suppressed.is_empty());
    }
}
