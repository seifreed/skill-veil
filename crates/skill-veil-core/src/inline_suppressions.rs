use crate::findings::Finding;
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

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
    let standalone_regex = Regex::new(
        r#"(?i)^\s*(?:<!--|#|//|/\*+|\*|;|--)?\s*(?:skill-veil:)?(ignore-next-line|ignore|nosemgrep-next-line|nosemgrep|nosem-next-line|nosem)\b(?:[:\s]+([A-Za-z0-9*_,.\-]+))?"#,
    )
    .expect("valid standalone suppression regex");
    let inline_regex = Regex::new(
        r#"(?i)(?:skill-veil:)?(ignore-next-line|ignore|nosemgrep-next-line|nosemgrep|nosem-next-line|nosem)\b(?:[:\s]+([A-Za-z0-9*_,.\-]+))?(?:\s+(?:because|reason)[:=]\s*([^#]+))?"#,
    )
    .expect("valid inline suppression regex");

    let mut suppressions = Vec::new();
    let lines: Vec<_> = content.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        let line_number = index + 1;
        if let Some(capture) = standalone_regex.captures(line) {
            add_suppressions_from_capture(
                &mut suppressions,
                &artifact_path,
                line_number,
                true,
                next_significant_line(&lines, index).unwrap_or(line_number + 1),
                &capture,
            );
            continue;
        }

        for capture in inline_regex.captures_iter(line) {
            add_suppressions_from_capture(
                &mut suppressions,
                &artifact_path,
                line_number,
                false,
                line_number + 1,
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
    next_line_number: usize,
    capture: &regex::Captures<'_>,
) {
    let Some(kind) = capture.get(1).map(|m| m.as_str().to_ascii_lowercase()) else {
        return;
    };
    let rule_list = capture.get(2).map(|m| m.as_str()).unwrap_or("*");
    let reason = capture.get(3).map(|m| m.as_str().trim().to_string());
    let applies_to_line = if kind.ends_with("next-line") || standalone {
        Some(next_line_number)
    } else if kind == "ignore" {
        None // file-wide suppression
    } else {
        // nosem / nosemgrep: suppress on the current line (not next-line, not file-wide)
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
            (!trimmed.is_empty()
                && trimmed != "```"
                && !trimmed.starts_with("```")
                && !trimmed.starts_with("<!--")
                && !trimmed.starts_with('#'))
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
                let object = entry.as_object()?;
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
                    path: artifact_path.clone(),
                    rule_id,
                    applies_to_line: None,
                    kind: "ignore".to_string(),
                    reason,
                    expires_at,
                })
            })
            .collect();
    }

    Vec::new()
}

pub(crate) fn collect_inline_suppressions(
    sources: &HashMap<PathBuf, String>,
) -> Vec<InlineSuppression> {
    let mut suppressions = Vec::new();
    for (path, content) in sources {
        suppressions.extend(collect_comment_suppressions(path, content));
        suppressions.extend(collect_json_suppressions(path, content));
    }
    suppressions
}

pub(crate) fn apply_inline_suppressions(
    findings: Vec<Finding>,
    suppressions: &[InlineSuppression],
) -> (Vec<Finding>, usize) {
    if suppressions.is_empty() {
        return (findings, 0);
    }

    let now = Utc::now();
    let original_len = findings.len();
    let filtered: Vec<_> = findings
        .into_iter()
        .filter(|finding| {
            !suppressions.iter().any(|suppression| {
                if suppression
                    .expires_at
                    .is_some_and(|expires_at| expires_at < now)
                {
                    return false;
                }
                let path_matches = finding
                    .artifact_path
                    .as_ref()
                    .is_none_or(|artifact_path| {
                        artifact_path == &suppression.path
                            || std::path::Path::new(artifact_path).ends_with(&suppression.path)
                    });
                let rule_matches =
                    suppression.rule_id == "*" || suppression.rule_id == finding.rule_id;
                let line_matches = suppression.applies_to_line.is_none_or(|line| {
                    finding
                        .line_number
                        .is_some_and(|finding_line| finding_line == line)
                });

                path_matches && rule_matches && line_matches
            })
        })
        .collect();

    let suppressed_count = original_len.saturating_sub(filtered.len());
    (filtered, suppressed_count)
}
