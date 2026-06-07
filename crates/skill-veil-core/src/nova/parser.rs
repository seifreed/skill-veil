//! NOVA `.nov` rule file parser.
//!
//! The DSL is small enough that a hand-written tokenizer + recursive
//! descent reads cleanly and avoids pulling in `nom`/`pest`. The
//! grammar mirrors the upstream NOVA Python parser, with two
//! deliberate differences:
//!
//! 1. Comments. Upstream supports `//` line comments. We accept the
//!    same.
//! 2. Pattern values. Upstream allows both `"…"` and `'…'` for
//!    keyword strings; semantics / LLM strings are double-quoted only.
//!    We follow upstream verbatim — single quotes are accepted only
//!    inside `keywords:`.

use super::condition::{ConditionExpr, Quantifier, QuantifierTarget, Section};
use super::model::{KeywordPattern, LlmPattern, NovaRule, SemanticPattern};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("rule must declare `rule <Name> {{`, got `{0}`")]
    MissingRuleHeader(String),
    #[error("unexpected end of input while parsing {0}")]
    UnexpectedEof(&'static str),
    #[error("unexpected token `{got}` while parsing {context}")]
    UnexpectedToken { context: &'static str, got: String },
    #[error("duplicate variable `{var}` in section `{section}`")]
    DuplicateVariable { section: &'static str, var: String },
    #[error("invalid threshold `{0}` (must be a float in [0.0, 1.0])")]
    InvalidThreshold(String),
    #[error("unknown section `{0}` (expected meta / keywords / semantics / llm / condition)")]
    UnknownSection(String),
    #[error("malformed line in section `{section}`: `{line}` ({reason})")]
    MalformedLine {
        section: &'static str,
        line: String,
        reason: &'static str,
    },
    #[error("invalid regex `{pattern}`: {source}")]
    InvalidRegex {
        pattern: String,
        #[source]
        source: regex::Error,
    },
    #[error("condition section is empty")]
    EmptyCondition,
    #[error("condition references unknown section `{0}`")]
    UnknownConditionSection(String),
    #[error("condition reference `{section}.${var}` does not match any pattern in the rule")]
    DanglingReference { section: Section, var: String },
    #[error("condition nesting exceeds the maximum depth of {max}")]
    ConditionTooDeep { max: usize },
}

/// Maximum nesting depth (parentheses + `not`) the condition expression
/// parser will descend before rejecting the rule. The parser is recursive
/// descent, so an attacker-supplied `.nov` whose condition is `((((…))))`
/// or `not not not …` would otherwise overflow the stack and abort the
/// process. Reachable via `rules test-pack --rules-dir <untrusted>` and
/// any operator-supplied pack. 256 is far beyond any real condition.
const MAX_CONDITION_DEPTH: usize = 256;

/// Parse the contents of a `.nov` file into a list of rules. NOVA
/// allows multiple rules per file; we yield them in source order.
pub fn parse_rules(input: &str) -> Result<Vec<NovaRule>, ParseError> {
    let mut rules = Vec::new();
    let mut cursor = 0usize;
    let bytes = input.as_bytes();

    while cursor < bytes.len() {
        skip_ws_and_comments(input, &mut cursor);
        if cursor >= bytes.len() {
            break;
        }
        let rule = parse_one_rule(input, &mut cursor)?;
        rules.push(rule);
    }

    Ok(rules)
}

fn skip_ws_and_comments(input: &str, cursor: &mut usize) {
    let bytes = input.as_bytes();
    while *cursor < bytes.len() {
        let c = bytes[*cursor];
        if c.is_ascii_whitespace() {
            *cursor += 1;
            continue;
        }
        // `//` line comment between top-level rules.
        if c == b'/' && *cursor + 1 < bytes.len() && bytes[*cursor + 1] == b'/' {
            while *cursor < bytes.len() && bytes[*cursor] != b'\n' {
                *cursor += 1;
            }
            continue;
        }
        return;
    }
}

fn parse_one_rule(input: &str, cursor: &mut usize) -> Result<NovaRule, ParseError> {
    let header = read_until_brace(input, cursor)?;
    let name = parse_rule_header(&header)?;

    let body_end = find_matching_brace(input, *cursor)?;
    let body = &input[*cursor..body_end];
    *cursor = body_end + 1; // step past `}`

    let mut rule = NovaRule {
        name: name.clone(),
        meta: BTreeMap::new(),
        keywords: BTreeMap::new(),
        semantics: BTreeMap::new(),
        llm: BTreeMap::new(),
        condition: ConditionExpr::Literal(false),
    };

    let sections = split_into_sections(body)?;
    for (section_name, section_body) in sections {
        match section_name.as_str() {
            "meta" => rule.meta = parse_meta(section_body)?,
            "keywords" => rule.keywords = parse_keywords(section_body)?,
            "semantics" => rule.semantics = parse_semantics(section_body)?,
            "llm" => rule.llm = parse_llm(section_body)?,
            "condition" => rule.condition = parse_condition(section_body)?,
            other => return Err(ParseError::UnknownSection(other.to_string())),
        }
    }

    validate_references(&mut rule)?;
    Ok(rule)
}

fn parse_rule_header(line: &str) -> Result<String, ParseError> {
    let trimmed = line.trim();
    let rest = trimmed
        .strip_prefix("rule")
        .ok_or_else(|| ParseError::MissingRuleHeader(trimmed.to_string()))?
        .trim_start();
    let mut name = String::new();
    for c in rest.chars() {
        if c.is_alphanumeric() || c == '_' {
            name.push(c);
        } else {
            break;
        }
    }
    if name.is_empty() {
        return Err(ParseError::MissingRuleHeader(trimmed.to_string()));
    }
    Ok(name)
}

fn read_until_brace(input: &str, cursor: &mut usize) -> Result<String, ParseError> {
    let bytes = input.as_bytes();
    let start = *cursor;
    while *cursor < bytes.len() {
        if bytes[*cursor] == b'{' {
            let header = &input[start..*cursor];
            *cursor += 1;
            return Ok(header.to_string());
        }
        *cursor += 1;
    }
    Err(ParseError::UnexpectedEof("rule header"))
}

fn find_matching_brace(input: &str, start: usize) -> Result<usize, ParseError> {
    let bytes = input.as_bytes();
    let mut depth: i32 = 1;
    let mut i = start;
    let mut in_dq_string = false;
    let mut in_sq_string = false;
    let mut in_regex = false;
    let mut in_line_comment = false;
    while i < bytes.len() {
        let c = bytes[i];
        if in_line_comment {
            if c == b'\n' {
                in_line_comment = false;
            }
            i += 1;
            continue;
        }
        if in_dq_string {
            if c == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if c == b'"' {
                in_dq_string = false;
            }
            i += 1;
            continue;
        }
        if in_sq_string {
            if c == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if c == b'\'' {
                in_sq_string = false;
            }
            i += 1;
            continue;
        }
        if in_regex {
            if c == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if c == b'/' {
                in_regex = false;
            }
            i += 1;
            continue;
        }
        // Line comment? Only when `//` appears outside any literal.
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            in_line_comment = true;
            i += 2;
            continue;
        }
        // Regex literal entry. Discriminator: `/` preceded by `=`,
        // `(`, `,`, or whitespace (i.e. position where a value
        // begins). The same heuristic as `find_unquoted`.
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] != b'/' {
            let prev_meaningful = input[..i].chars().rev().find(|c| !c.is_whitespace());
            if matches!(prev_meaningful, Some('=') | Some('(') | Some(',') | None) {
                in_regex = true;
                i += 1;
                continue;
            }
        }
        if c == b'"' {
            in_dq_string = true;
            i += 1;
            continue;
        }
        if c == b'\'' {
            let prev_meaningful = input[..i].chars().rev().find(|c| !c.is_whitespace());
            if matches!(prev_meaningful, Some('=') | Some('(') | Some(',') | None) {
                in_sq_string = true;
                i += 1;
                continue;
            }
        }
        if c == b'{' {
            depth += 1;
        } else if c == b'}' {
            depth -= 1;
            if depth == 0 {
                return Ok(i);
            }
        }
        i += 1;
    }
    Err(ParseError::UnexpectedEof("rule body"))
}

/// Walk the rule body and split it into `(section_name, body)` pairs.
/// A section starts at a line whose only non-whitespace, non-comment
/// content is `<name>:` and ends at the next section header or end-
/// of-body.
fn split_into_sections(body: &str) -> Result<Vec<(String, String)>, ParseError> {
    let mut sections: Vec<(String, String)> = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_body = String::new();

    for raw_line in body.lines() {
        let line = strip_line_comment(raw_line).trim_end();
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if current_name.is_some() {
                current_body.push('\n');
            }
            continue;
        }
        if let Some(stripped) = trimmed.strip_suffix(':') {
            // Section header line.
            if let Some(name) = current_name.take() {
                sections.push((name, std::mem::take(&mut current_body)));
            }
            current_name = Some(stripped.trim().to_lowercase());
            continue;
        }
        if current_name.is_none() {
            // Stray content before the first section header.
            return Err(ParseError::MalformedLine {
                section: "rule body",
                line: trimmed.to_string(),
                reason: "expected a section header (`meta:`, `keywords:`, …) first",
            });
        }
        current_body.push_str(line);
        current_body.push('\n');
    }
    if let Some(name) = current_name {
        sections.push((name, current_body));
    }
    Ok(sections)
}

fn strip_line_comment(line: &str) -> &str {
    if let Some(idx) = find_unquoted(line, "//") {
        &line[..idx]
    } else {
        line
    }
}

/// Find the first occurrence of `needle` in `haystack` that is NOT
/// inside a `"…"` or `/…/` literal. Used by the comment stripper so
/// `keywords: $x = /\\/foo/` doesn't get truncated at the slash.
fn find_unquoted(haystack: &str, needle: &str) -> Option<usize> {
    let bytes = haystack.as_bytes();
    let nb = needle.as_bytes();
    let mut in_dq_string = false;
    let mut in_sq_string = false;
    let mut in_regex = false;
    let mut i = 0;
    while i + nb.len() <= bytes.len() {
        let c = bytes[i];
        if in_dq_string {
            if c == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if c == b'"' {
                in_dq_string = false;
            }
            i += 1;
            continue;
        }
        if in_sq_string {
            if c == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if c == b'\'' {
                in_sq_string = false;
            }
            i += 1;
            continue;
        }
        if in_regex {
            if c == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if c == b'/' {
                in_regex = false;
            }
            i += 1;
            continue;
        }
        if c == b'"' {
            in_dq_string = true;
            i += 1;
            continue;
        }
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] != b'/' {
            let prev_meaningful = haystack[..i].chars().rev().find(|c| !c.is_whitespace());
            if matches!(prev_meaningful, Some('=') | Some('(') | Some(',')) {
                in_regex = true;
                i += 1;
                continue;
            }
        }
        if c == b'\'' {
            let prev_meaningful = haystack[..i].chars().rev().find(|c| !c.is_whitespace());
            if matches!(prev_meaningful, Some('=') | Some('(') | Some(',')) {
                in_sq_string = true;
                i += 1;
                continue;
            }
        }
        if &bytes[i..i + nb.len()] == nb {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Yield each meaningful line of a NOVA section body: comment-stripped,
/// trimmed, with blank lines skipped. Every `parse_*` section consumes
/// lines through this one definition so the skip-empty rule cannot drift.
fn section_lines(body: &str) -> impl Iterator<Item = &str> {
    body.lines()
        .map(|raw| strip_line_comment(raw).trim())
        .filter(|line| !line.is_empty())
}

/// Parse a `$var = <value>` section into a map, rejecting duplicate
/// variables. The per-section value grammar is supplied by `parse_value`;
/// the variable-binding spine (split, dedup, insert) is shared by the
/// `keywords`, `semantics`, and `llm` sections.
fn parse_var_assignments<T>(
    body: &str,
    section: &'static str,
    mut parse_value: impl FnMut(&str) -> Result<T, ParseError>,
) -> Result<BTreeMap<String, T>, ParseError> {
    let mut out = BTreeMap::new();
    for line in section_lines(body) {
        let (var, value) = split_var_assignment(line, section)?;
        if out.contains_key(&var) {
            return Err(ParseError::DuplicateVariable { section, var });
        }
        out.insert(var, parse_value(value)?);
    }
    Ok(out)
}

fn parse_meta(body: String) -> Result<BTreeMap<String, String>, ParseError> {
    let mut out = BTreeMap::new();
    for line in section_lines(&body) {
        let Some((key, value)) = line.split_once('=') else {
            return Err(ParseError::MalformedLine {
                section: "meta",
                line: line.to_string(),
                reason: "missing `=` between key and value",
            });
        };
        let key = key.trim().to_string();
        let value = strip_string_quotes(value.trim());
        out.insert(key, value);
    }
    Ok(out)
}

fn strip_string_quotes(value: &str) -> String {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return value[1..value.len() - 1].to_string();
        }
    }
    value.to_string()
}

fn parse_keywords(body: String) -> Result<BTreeMap<String, KeywordPattern>, ParseError> {
    parse_var_assignments(&body, "keywords", parse_keyword_value)
}

fn parse_keyword_value(raw: &str) -> Result<KeywordPattern, ParseError> {
    let value = raw.trim();
    let bytes = value.as_bytes();

    // Regex form: /pattern/ or /pattern/i
    if value.starts_with('/') {
        // Find the closing `/`. Walk from the end since the pattern
        // may itself contain `/` chars (escaped or not).
        let trailing_i = if value.ends_with('/') {
            false
        } else {
            value.ends_with("/i")
        };
        let closing = if trailing_i {
            value.len() - 2
        } else if value.ends_with('/') {
            value.len() - 1
        } else {
            return Err(ParseError::MalformedLine {
                section: "keywords",
                line: raw.to_string(),
                reason: "regex pattern is not closed with `/` or `/i`",
            });
        };
        // A lone `/` or `/i` has its opening and "closing" delimiter at the
        // same position, so `closing == 0` and `value[1..0]` would panic.
        // Treat a delimiter pair with no body between them as malformed
        // rather than crashing the whole scan on one bad rule line.
        if closing < 1 {
            return Err(ParseError::MalformedLine {
                section: "keywords",
                line: raw.to_string(),
                reason: "regex pattern is not closed with `/` or `/i`",
            });
        }
        let body = &value[1..closing];
        // Upstream NOVA defaults EVERY keyword pattern (regex and literal) to
        // case-INSENSITIVE; the `/i` suffix is the explicit-but-redundant form,
        // not what controls case. A bare `/abc/` therefore matches `ABC` too.
        // Pre-fix this branch made bare regexes case-SENSITIVE (only `/i` was
        // insensitive), so capitalised injection/malware keywords evaded every
        // NOVA keyword-regex rule that omitted `/i` — and it disagreed with the
        // string-literal branch below, which is already case-insensitive.
        // (`trailing_i` still drives `closing` above so the suffix is stripped.)
        let case_sensitive = false;
        crate::regex_bounds::build_bounded_regex(body).map_err(|source| {
            ParseError::InvalidRegex {
                pattern: body.to_string(),
                source,
            }
        })?;
        return Ok(KeywordPattern {
            pattern: body.to_string(),
            is_regex: true,
            case_sensitive,
        });
    }

    // String form: "pattern" or 'pattern'
    if bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
    {
        let inner = &value[1..value.len() - 1];
        return Ok(KeywordPattern {
            pattern: inner.to_string(),
            is_regex: false,
            case_sensitive: false,
        });
    }

    Err(ParseError::MalformedLine {
        section: "keywords",
        line: raw.to_string(),
        reason: "value must be quoted (\"…\" / '…') or a regex (/…/ or /…/i)",
    })
}

fn parse_semantics(body: String) -> Result<BTreeMap<String, SemanticPattern>, ParseError> {
    parse_var_assignments(&body, "semantics", |value| {
        let (pattern, threshold) = parse_pattern_with_threshold(value, "semantics", 0.1)?;
        Ok(SemanticPattern { pattern, threshold })
    })
}

fn parse_llm(body: String) -> Result<BTreeMap<String, LlmPattern>, ParseError> {
    parse_var_assignments(&body, "llm", |value| {
        let (pattern, threshold) = parse_pattern_with_threshold(value, "llm", 0.1)?;
        Ok(LlmPattern { pattern, threshold })
    })
}

fn parse_pattern_with_threshold(
    raw: &str,
    section: &'static str,
    default_threshold: f32,
) -> Result<(String, f32), ParseError> {
    let value = raw.trim();
    // Pattern may be: "text" optionally followed by `(threshold)`.
    if !value.starts_with('"') {
        return Err(ParseError::MalformedLine {
            section,
            line: value.to_string(),
            reason: "pattern must start with a double-quoted string",
        });
    }
    // Find the closing double-quote (no escape support; matches the
    // upstream parser).
    let bytes = value.as_bytes();
    let close = bytes
        .iter()
        .enumerate()
        .skip(1)
        .find_map(|(i, b)| if *b == b'"' { Some(i) } else { None });
    let close = close.ok_or(ParseError::MalformedLine {
        section,
        line: value.to_string(),
        reason: "pattern string is not closed",
    })?;
    let pattern = value[1..close].to_string();
    let rest = value[close + 1..].trim();

    let threshold = if rest.is_empty() {
        default_threshold
    } else {
        let inner = rest
            .strip_prefix('(')
            .and_then(|s| s.strip_suffix(')'))
            .ok_or(ParseError::MalformedLine {
                section,
                line: value.to_string(),
                reason: "trailing threshold must be enclosed in parentheses",
            })?
            .trim();
        let parsed: f32 = inner
            .parse()
            .map_err(|_| ParseError::InvalidThreshold(inner.to_string()))?;
        if !(0.0..=1.0).contains(&parsed) {
            return Err(ParseError::InvalidThreshold(inner.to_string()));
        }
        parsed
    };

    Ok((pattern, threshold))
}

fn split_var_assignment<'a>(
    line: &'a str,
    section: &'static str,
) -> Result<(String, &'a str), ParseError> {
    let (key, value) = line.split_once('=').ok_or(ParseError::MalformedLine {
        section,
        line: line.to_string(),
        reason: "missing `=` between variable and pattern",
    })?;
    let key = key.trim();
    let stripped = key.strip_prefix('$').ok_or(ParseError::MalformedLine {
        section,
        line: line.to_string(),
        reason: "variable name must start with `$`",
    })?;
    // Store names WITHOUT the leading `$` so they round-trip cleanly
    // with condition references (the condition tokenizer also strips
    // the `$`). The trade-off: a rule cannot have variables `$foo`
    // and `foo` distinguished by the dollar sign — but that's a
    // NOVA-level constraint not a parser one (NOVA mandates `$`).
    Ok((stripped.to_string(), value.trim()))
}

fn parse_condition(body: String) -> Result<ConditionExpr, ParseError> {
    let cleaned: String = body
        .lines()
        .map(strip_line_comment)
        .collect::<Vec<_>>()
        .join(" ");
    let normalized = normalize_whitespace(&cleaned);
    if normalized.trim().is_empty() {
        return Err(ParseError::EmptyCondition);
    }
    let tokens = tokenize_condition(&normalized)?;
    let mut iter = TokenIter::new(tokens);
    let expr = parse_or(&mut iter)?;
    if let Some(extra) = iter.peek() {
        return Err(ParseError::UnexpectedToken {
            context: "condition (trailing input)",
            got: format!("{extra:?}"),
        });
    }
    Ok(expr)
}

fn normalize_whitespace(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_ws = false;
    for c in input.chars() {
        if c.is_whitespace() {
            if !prev_ws {
                out.push(' ');
                prev_ws = true;
            }
        } else {
            out.push(c);
            prev_ws = false;
        }
    }
    out.trim().to_string()
}

#[derive(Debug, Clone, PartialEq)]
enum CondToken {
    LParen,
    RParen,
    Dot,
    Star,
    Comma,
    Ident(String),
    Var(String), // includes the leading `$`
    Number(u32),
    KwAnd,
    KwOr,
    KwNot,
    KwOf,
    KwAny,
    KwAll,
    KwTrue,
    KwFalse,
}

fn tokenize_condition(input: &str) -> Result<Vec<CondToken>, ParseError> {
    let mut out = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        match c {
            b'(' => {
                out.push(CondToken::LParen);
                i += 1;
            }
            b')' => {
                out.push(CondToken::RParen);
                i += 1;
            }
            b'.' => {
                out.push(CondToken::Dot);
                i += 1;
            }
            b'*' => {
                out.push(CondToken::Star);
                i += 1;
            }
            b',' => {
                out.push(CondToken::Comma);
                i += 1;
            }
            b'$' => {
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                    j += 1;
                }
                if start == j {
                    return Err(ParseError::UnexpectedToken {
                        context: "condition (variable name)",
                        got: "$".into(),
                    });
                }
                out.push(CondToken::Var(input[start..j].to_string()));
                i = j;
            }
            d if d.is_ascii_digit() => {
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                let n: u32 = input[start..i]
                    .parse()
                    .map_err(|_| ParseError::UnexpectedToken {
                        context: "condition (integer)",
                        got: input[start..i].to_string(),
                    })?;
                out.push(CondToken::Number(n));
            }
            a if a.is_ascii_alphabetic() || a == b'_' => {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let word = &input[start..i];
                let token = match word.to_ascii_lowercase().as_str() {
                    "and" => CondToken::KwAnd,
                    "or" => CondToken::KwOr,
                    "not" => CondToken::KwNot,
                    "of" => CondToken::KwOf,
                    "any" => CondToken::KwAny,
                    "all" => CondToken::KwAll,
                    "true" => CondToken::KwTrue,
                    "false" => CondToken::KwFalse,
                    _ => CondToken::Ident(word.to_string()),
                };
                out.push(token);
            }
            other => {
                return Err(ParseError::UnexpectedToken {
                    context: "condition (lexer)",
                    got: (other as char).to_string(),
                });
            }
        }
    }
    Ok(out)
}

struct TokenIter {
    tokens: Vec<CondToken>,
    pos: usize,
    depth: usize,
}

impl TokenIter {
    fn new(tokens: Vec<CondToken>) -> Self {
        Self {
            tokens,
            pos: 0,
            depth: 0,
        }
    }

    /// Enter one recursion level, rejecting input that nests past
    /// [`MAX_CONDITION_DEPTH`]. Paired with [`Self::leave`] on the success
    /// path so that wide-but-shallow conditions (`(a) or (b) or …`) do not
    /// accumulate depth across sibling branches.
    fn enter(&mut self) -> Result<(), ParseError> {
        self.depth += 1;
        if self.depth > MAX_CONDITION_DEPTH {
            Err(ParseError::ConditionTooDeep {
                max: MAX_CONDITION_DEPTH,
            })
        } else {
            Ok(())
        }
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn peek(&self) -> Option<&CondToken> {
        self.tokens.get(self.pos)
    }
    fn bump(&mut self) -> Option<CondToken> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }
    fn eat(&mut self, want: &CondToken) -> bool {
        if self.peek() == Some(want) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
}

fn parse_or(iter: &mut TokenIter) -> Result<ConditionExpr, ParseError> {
    let mut items = vec![parse_and(iter)?];
    while iter.eat(&CondToken::KwOr) {
        items.push(parse_and(iter)?);
    }
    if items.len() == 1 {
        Ok(items.pop().unwrap())
    } else {
        Ok(ConditionExpr::Or(items))
    }
}

fn parse_and(iter: &mut TokenIter) -> Result<ConditionExpr, ParseError> {
    let mut items = vec![parse_not(iter)?];
    while iter.eat(&CondToken::KwAnd) {
        items.push(parse_not(iter)?);
    }
    if items.len() == 1 {
        Ok(items.pop().unwrap())
    } else {
        Ok(ConditionExpr::And(items))
    }
}

fn parse_not(iter: &mut TokenIter) -> Result<ConditionExpr, ParseError> {
    if iter.eat(&CondToken::KwNot) {
        iter.enter()?;
        let inner = parse_not(iter)?;
        iter.leave();
        return Ok(ConditionExpr::Not(Box::new(inner)));
    }
    parse_atom(iter)
}

fn parse_atom(iter: &mut TokenIter) -> Result<ConditionExpr, ParseError> {
    let next = iter
        .bump()
        .ok_or(ParseError::UnexpectedEof("condition atom"))?;
    match next {
        CondToken::LParen => {
            iter.enter()?;
            let inner = parse_or(iter)?;
            iter.leave();
            if !iter.eat(&CondToken::RParen) {
                return Err(ParseError::UnexpectedToken {
                    context: "condition (expected `)`)",
                    got: format!("{:?}", iter.peek()),
                });
            }
            Ok(inner)
        }
        CondToken::KwTrue => Ok(ConditionExpr::Literal(true)),
        CondToken::KwFalse => Ok(ConditionExpr::Literal(false)),
        CondToken::KwAny => parse_quantifier_tail(iter, Quantifier::Any),
        CondToken::KwAll => parse_quantifier_tail(iter, Quantifier::All),
        CondToken::Number(n) => parse_quantifier_tail(iter, Quantifier::AtLeast(n)),
        CondToken::Ident(section_name) => parse_section_atom(iter, &section_name),
        // Bare `$var` reference (no section prefix). NOVA's
        // canonical parser auto-resolves these by searching every
        // pattern dictionary; we keep an unresolved marker and
        // resolve it at validate-references time, so the error
        // message can name the missing var instead of just
        // "unknown reference".
        CondToken::Var(name) => Ok(ConditionExpr::Reference {
            // `Section::Keywords` is a placeholder that
            // `validate_references` will rewrite once it figures out
            // which section actually defines `$name`.
            section: Section::Keywords,
            var: format!("__bare__:{name}"),
        }),
        other => Err(ParseError::UnexpectedToken {
            context: "condition atom",
            got: format!("{other:?}"),
        }),
    }
}

fn parse_quantifier_tail(iter: &mut TokenIter, q: Quantifier) -> Result<ConditionExpr, ParseError> {
    if !iter.eat(&CondToken::KwOf) {
        return Err(ParseError::UnexpectedToken {
            context: "condition (expected `of` after quantifier)",
            got: format!("{:?}", iter.peek()),
        });
    }
    let target = parse_quantifier_target(iter)?;
    Ok(ConditionExpr::Quantified {
        quantifier: q,
        target: Box::new(target),
    })
}

fn parse_quantifier_target(iter: &mut TokenIter) -> Result<QuantifierTarget, ParseError> {
    // Fast path: `<section>.*` — by far the common shape.
    if let Some(CondToken::Ident(section_name)) = iter.peek().cloned() {
        let saved_pos = iter.pos;
        iter.bump(); // consume ident
        if iter.eat(&CondToken::Dot) && iter.eat(&CondToken::Star) {
            let section = Section::from_str(&section_name)
                .ok_or(ParseError::UnknownConditionSection(section_name))?;
            return Ok(QuantifierTarget::SectionWildcard(section));
        }
        iter.pos = saved_pos;
    }
    if iter.eat(&CondToken::LParen) {
        let first = parse_or(iter)?;
        let mut items = vec![first];
        while iter.eat(&CondToken::Comma) {
            items.push(parse_or(iter)?);
        }
        if !iter.eat(&CondToken::RParen) {
            return Err(ParseError::UnexpectedToken {
                context: "condition (expected `)` after quantifier target)",
                got: format!("{:?}", iter.peek()),
            });
        }
        let inner = if items.len() == 1 {
            items.pop().unwrap()
        } else {
            ConditionExpr::Or(items)
        };
        return Ok(QuantifierTarget::Inner(Box::new(inner)));
    }
    // Fallback: `any of <expr>` where `<expr>` is anything else the
    // atom parser accepts (e.g. `keywords.$x`, `$bare_var`,
    // `semantics.$prefix*`). Wrap it as an Inner target so the
    // evaluator treats it as a 1-element group.
    let expr = parse_atom(iter)?;
    Ok(QuantifierTarget::Inner(Box::new(expr)))
}

fn parse_section_atom(
    iter: &mut TokenIter,
    section_name: &str,
) -> Result<ConditionExpr, ParseError> {
    if !iter.eat(&CondToken::Dot) {
        return Err(ParseError::UnexpectedToken {
            context: "condition (expected `.` after section name)",
            got: format!("{:?}", iter.peek()),
        });
    }
    let section = Section::from_str(section_name)
        .ok_or_else(|| ParseError::UnknownConditionSection(section_name.to_string()))?;
    if iter.eat(&CondToken::Star) {
        return Ok(ConditionExpr::Wildcard { section });
    }
    let next = iter
        .bump()
        .ok_or(ParseError::UnexpectedEof("condition (variable name)"))?;
    match next {
        CondToken::Var(name) => {
            // `<section>.$var*` is the variable-prefix wildcard form
            // (e.g. `semantics.$injection*` from `ttps.nov`). Treat
            // `$var` followed by `*` as a single PrefixWildcard.
            if iter.eat(&CondToken::Star) {
                Ok(ConditionExpr::PrefixWildcard {
                    section,
                    prefix: name,
                })
            } else {
                Ok(ConditionExpr::Reference { section, var: name })
            }
        }
        other => Err(ParseError::UnexpectedToken {
            context: "condition (expected `*` or `$var` after section name)",
            got: format!("{other:?}"),
        }),
    }
}

/// Validate every condition reference resolves, AND rewrite bare
/// `$var` references (parsed with the placeholder marker
/// `__bare__:<name>`) to the section that actually defines them.
/// Bare references that match patterns in multiple sections are
/// rejected — the NOVA Python parser leaves the resolution implicit
/// but real rules in the canonical pack don't reuse names across
/// sections, and ambiguity here would silently change semantics.
fn validate_references(rule: &mut NovaRule) -> Result<(), ParseError> {
    let snapshot_keys = (
        rule.keywords.keys().cloned().collect::<Vec<_>>(),
        rule.semantics.keys().cloned().collect::<Vec<_>>(),
        rule.llm.keys().cloned().collect::<Vec<_>>(),
    );
    rewrite_bare_refs(&mut rule.condition, &snapshot_keys)?;
    check_refs(&rule.condition, rule)
}

fn rewrite_bare_refs(
    expr: &mut ConditionExpr,
    keys: &(Vec<String>, Vec<String>, Vec<String>),
) -> Result<(), ParseError> {
    const BARE_PREFIX: &str = "__bare__:";
    match expr {
        ConditionExpr::Reference { section, var } => {
            if let Some(name) = var.strip_prefix(BARE_PREFIX) {
                let in_kw = keys.0.iter().any(|k| k == name);
                let in_sem = keys.1.iter().any(|k| k == name);
                let in_llm = keys.2.iter().any(|k| k == name);
                let count = u8::from(in_kw) + u8::from(in_sem) + u8::from(in_llm);
                let resolved_section = if in_kw {
                    Section::Keywords
                } else if in_sem {
                    Section::Semantics
                } else if in_llm {
                    Section::Llm
                } else {
                    return Err(ParseError::DanglingReference {
                        section: Section::Keywords,
                        var: name.to_string(),
                    });
                };
                if count > 1 {
                    return Err(ParseError::DanglingReference {
                        section: resolved_section,
                        var: format!("{name} (ambiguous: defined in multiple sections)"),
                    });
                }
                *section = resolved_section;
                *var = name.to_string();
            }
            Ok(())
        }
        ConditionExpr::PrefixWildcard { .. }
        | ConditionExpr::Wildcard { .. }
        | ConditionExpr::Literal(_) => Ok(()),
        ConditionExpr::Not(inner) => rewrite_bare_refs(inner, keys),
        ConditionExpr::And(items) | ConditionExpr::Or(items) => {
            for item in items {
                rewrite_bare_refs(item, keys)?;
            }
            Ok(())
        }
        ConditionExpr::Quantified { target, .. } => match target.as_mut() {
            QuantifierTarget::SectionWildcard(_) => Ok(()),
            QuantifierTarget::Inner(inner) => rewrite_bare_refs(inner, keys),
        },
    }
}

fn check_refs(expr: &ConditionExpr, rule: &NovaRule) -> Result<(), ParseError> {
    match expr {
        ConditionExpr::Reference { section, var } => {
            let exists = match section {
                Section::Keywords => rule.keywords.contains_key(var),
                Section::Semantics => rule.semantics.contains_key(var),
                Section::Llm => rule.llm.contains_key(var),
            };
            if !exists {
                return Err(ParseError::DanglingReference {
                    section: *section,
                    var: var.clone(),
                });
            }
            Ok(())
        }
        ConditionExpr::PrefixWildcard { section, prefix } => {
            let any_match = match section {
                Section::Keywords => rule.keywords.keys().any(|k| k.starts_with(prefix)),
                Section::Semantics => rule.semantics.keys().any(|k| k.starts_with(prefix)),
                Section::Llm => rule.llm.keys().any(|k| k.starts_with(prefix)),
            };
            if !any_match {
                return Err(ParseError::DanglingReference {
                    section: *section,
                    var: format!("{prefix}* (no patterns match this prefix)"),
                });
            }
            Ok(())
        }
        ConditionExpr::Wildcard { section } => reject_empty_section_wildcard(*section, rule),
        ConditionExpr::Literal(_) => Ok(()),
        ConditionExpr::Not(inner) => check_refs(inner, rule),
        ConditionExpr::And(items) | ConditionExpr::Or(items) => {
            for item in items {
                check_refs(item, rule)?;
            }
            Ok(())
        }
        ConditionExpr::Quantified { target, .. } => match target.as_ref() {
            QuantifierTarget::SectionWildcard(section) => {
                reject_empty_section_wildcard(*section, rule)
            }
            QuantifierTarget::Inner(inner) => check_refs(inner, rule),
        },
    }
}

/// Reject a wildcard / `<n> of <section>.*` whose section declares no
/// patterns. Such a target is vacuously `false`, so under `not` it inverts to
/// `true` and the rule fires on every body with zero evidence. Mirrors the
/// dangling-`Reference` and no-prefix-match `PrefixWildcard` rejections so a
/// wildcard over an empty section is a parse error, not a silent always-match.
fn reject_empty_section_wildcard(section: Section, rule: &NovaRule) -> Result<(), ParseError> {
    let is_empty = match section {
        Section::Keywords => rule.keywords.is_empty(),
        Section::Semantics => rule.semantics.is_empty(),
        Section::Llm => rule.llm.is_empty(),
    };
    if is_empty {
        return Err(ParseError::DanglingReference {
            section,
            var: "* (section declares no patterns)".to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nova::condition::{ConditionExpr, Section};

    /// # Contract
    ///
    /// A condition nested past [`MAX_CONDITION_DEPTH`] is REJECTED with a
    /// typed error, never a stack overflow. The recursive-descent
    /// condition parser is otherwise reachable with attacker-supplied
    /// `.nov` files (`rules test-pack --rules-dir <untrusted>`), where
    /// `((((…))))` would abort the process.
    #[test]
    fn condition_nesting_beyond_max_depth_is_rejected_not_overflow() {
        let depth = MAX_CONDITION_DEPTH + 50;
        let body = format!(
            "rule Deep {{\n    keywords:\n        $a = \"x\"\n    condition:\n        {}keywords.$a{}\n}}\n",
            "(".repeat(depth),
            ")".repeat(depth),
        );
        let err = parse_rules(&body).expect_err("deep nesting must error, not overflow");
        assert!(
            matches!(err, ParseError::ConditionTooDeep { .. }),
            "expected ConditionTooDeep, got {err:?}"
        );
    }

    /// # Contract (negative)
    ///
    /// A wide-but-shallow condition (`(a) or (b) or …`) must NOT trip the
    /// depth guard — each parenthesised branch enters and leaves one
    /// level, so sibling branches do not accumulate depth.
    #[test]
    fn wide_shallow_condition_parses() {
        let terms = vec!["(keywords.$a)"; 300].join(" or ");
        let body = format!(
            "rule Wide {{\n    keywords:\n        $a = \"x\"\n    condition:\n        {terms}\n}}\n"
        );
        assert!(
            parse_rules(&body).is_ok(),
            "wide flat condition must parse without tripping the depth guard"
        );
    }

    #[test]
    fn parses_minimal_keywords_only_rule() {
        let body = r#"
            rule MinimalKW {
                meta:
                    description = "Tiny"
                    severity = "low"
                keywords:
                    $a = "foo"
                    $b = /bar\d+/
                condition:
                    keywords.$a or keywords.$b
            }
        "#;
        let rules = parse_rules(body).unwrap();
        assert_eq!(rules.len(), 1);
        let r = &rules[0];
        assert_eq!(r.name, "MinimalKW");
        assert_eq!(r.meta.get("severity").map(String::as_str), Some("low"));
        assert_eq!(r.keywords.len(), 2);
        let a = &r.keywords["a"];
        assert_eq!(a.pattern, "foo");
        assert!(!a.is_regex);
        let b = &r.keywords["b"];
        assert!(b.is_regex);
        assert_eq!(b.pattern, "bar\\d+");
    }

    #[test]
    fn parses_real_inject_dynamic_context_rule() {
        let body = r#"
rule InjectDynamicContext
{
    meta:
        description = "Detects dynamic context injection inside agent skills."
        author = "Marco Pedrinazzi (@pedrinazziM)"
        version = "1.0.0"
        category = "abusing_functions/agentic_misuse"
        severity = "high"
        date = "2026-03-18"

    keywords:
        $command_placeholder = /!\`.+?\`/

    condition:
        keywords.$command_placeholder
}"#;
        let rules = parse_rules(body).unwrap();
        assert_eq!(rules.len(), 1);
        let r = &rules[0];
        assert_eq!(r.name, "InjectDynamicContext");
        assert!(r.keywords["command_placeholder"].is_regex);
        assert_eq!(r.meta["severity"], "high");
        // Condition should be a single Reference.
        assert!(matches!(
            r.condition,
            ConditionExpr::Reference {
                section: Section::Keywords,
                ..
            }
        ));
    }

    #[test]
    fn parses_semantics_threshold_default_and_custom() {
        let body = r#"
            rule SemanticsTest {
                semantics:
                    $no_threshold = "phrase A"
                    $custom = "phrase B" (0.42)
                condition:
                    semantics.$no_threshold or semantics.$custom
            }
        "#;
        let rules = parse_rules(body).unwrap();
        let r = &rules[0];
        assert!((r.semantics["no_threshold"].threshold - 0.1).abs() < 1e-6);
        assert!((r.semantics["custom"].threshold - 0.42).abs() < 1e-6);
    }

    /// Contract: dangling condition references (typo'd `$var`)
    /// surface at parse time with a named error so the rule never
    /// loads silently broken.
    #[test]
    fn rejects_dangling_condition_reference() {
        let body = r#"
            rule BadRef {
                keywords:
                    $real = "x"
                condition:
                    keywords.$missing
            }
        "#;
        let err = parse_rules(body).expect_err("dangling ref must error");
        assert!(matches!(
            err,
            ParseError::DanglingReference {
                section: Section::Keywords,
                ..
            }
        ));
    }

    /// # Contract
    ///
    /// A wildcard over a section that declares no patterns is rejected at
    /// parse time. Such a target is vacuously `false`, so `not <section>.*`
    /// inverts to `true` and would fire the rule on every body with zero
    /// evidence — the rule must never load.
    #[test]
    fn rejects_negated_wildcard_over_empty_section() {
        let body = r#"
            rule AlwaysFires {
                keywords:
                    $k = "anything"
                condition:
                    not semantics.*
            }
        "#;
        let err = parse_rules(body).expect_err("wildcard over an empty section must error");
        assert!(
            matches!(
                err,
                ParseError::DanglingReference {
                    section: Section::Semantics,
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    /// # Contract
    ///
    /// The quantified form (`any of <section>.*`) over an empty section is
    /// rejected for the same reason — `not any of semantics.*` over an empty
    /// section is also vacuously firing.
    #[test]
    fn rejects_quantified_wildcard_over_empty_section() {
        let body = r#"
            rule QuantAlwaysFires {
                keywords:
                    $k = "anything"
                condition:
                    not any of semantics.*
            }
        "#;
        let err = parse_rules(body).expect_err("quantified wildcard over empty section must error");
        assert!(
            matches!(
                err,
                ParseError::DanglingReference {
                    section: Section::Semantics,
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    /// # Contract (negative)
    ///
    /// A wildcard over a POPULATED section still validates — the rejection is
    /// scoped strictly to empty sections, so legitimate `any of X.*` rules are
    /// unaffected.
    #[test]
    fn wildcard_over_populated_section_validates() {
        let body = r#"
            rule UsesSemantics {
                semantics:
                    $s = "exfiltrate the user's data"
                condition:
                    not semantics.*
            }
        "#;
        assert!(
            parse_rules(body).is_ok(),
            "wildcard over a populated section must validate"
        );
    }

    /// Contract: `any of X.*` parses as `Quantified { Any,
    /// SectionWildcard }`. The bare `X.*` parses as `Wildcard`.
    /// Both forms must be accepted.
    #[test]
    fn parses_both_bare_wildcard_and_any_of_wildcard() {
        let bare = parse_condition("keywords.*".to_string()).unwrap();
        assert!(matches!(
            bare,
            ConditionExpr::Wildcard {
                section: Section::Keywords
            }
        ));
        let any_of = parse_condition("any of semantics.*".to_string()).unwrap();
        assert!(matches!(
            any_of,
            ConditionExpr::Quantified {
                quantifier: super::super::condition::Quantifier::Any,
                ..
            }
        ));
    }

    /// Contract: `not A and B` parses with NOVA precedence (`not`
    /// binds tighter than `and`). The result tree must be
    /// `And([Not(A), B])`, NOT `Not(And([A, B]))`.
    #[test]
    fn boolean_precedence_matches_nova() {
        let cond = parse_condition("not keywords.$a and keywords.$b".to_string()).unwrap();
        match cond {
            ConditionExpr::And(items) => {
                assert_eq!(items.len(), 2);
                assert!(matches!(items[0], ConditionExpr::Not(_)));
                assert!(matches!(items[1], ConditionExpr::Reference { .. }));
            }
            other => panic!("expected And at top, got {other:?}"),
        }
    }

    /// Contract: line comments `// ...` are stripped from every
    /// section without breaking regex literals that contain `/`.
    #[test]
    fn line_comments_do_not_eat_regex_literals() {
        let body = r#"
            rule CommentRegex {
                // a comment before keywords
                keywords:
                    $x = /\/foo\// // trailing comment
                condition:
                    keywords.$x // condition comment
            }
        "#;
        let rules = parse_rules(body).unwrap();
        assert!(rules[0].keywords["x"].is_regex);
        assert_eq!(rules[0].keywords["x"].pattern, "\\/foo\\/");
    }

    /// Contract: a keyword regex whose automaton exceeds the shared size cap
    /// is rejected at parse time (community NOVA packs are attacker-influenced;
    /// the bound must apply on the NOVA path too, not just the YAML matcher).
    #[test]
    fn oversized_keyword_regex_is_rejected() {
        let body = r#"
            rule Bomb {
                keywords:
                    $x = /a{1000000}{2}/
                condition:
                    keywords.$x
            }
        "#;
        let err = parse_rules(body).expect_err("oversized regex must be rejected");
        assert!(matches!(err, ParseError::InvalidRegex { .. }));
    }

    /// Contract: `//` inside a single-quoted keyword literal is pattern
    /// content, not a line comment.
    #[test]
    fn line_comments_do_not_eat_single_quoted_keyword_literals() {
        let body = r#"
            rule SingleQuotedUrl {
                keywords:
                    $url = 'http://example.test/a//b' // trailing comment
                condition:
                    keywords.$url
            }
        "#;
        let rules = parse_rules(body).unwrap();
        assert_eq!(rules[0].keywords["url"].pattern, "http://example.test/a//b");
    }

    /// Contract: braces inside a single-quoted keyword literal do not
    /// terminate the enclosing rule body.
    #[test]
    fn brace_inside_single_quoted_keyword_literal_is_not_rule_close() {
        let body = r#"
            rule SingleQuotedBrace {
                keywords:
                    $brace = 'literal } brace'
                condition:
                    keywords.$brace
            }
        "#;
        let rules = parse_rules(body).unwrap();
        assert_eq!(rules[0].keywords["brace"].pattern, "literal } brace");
    }

    /// Contract: an apostrophe in an unquoted metadata value is not a
    /// single-quoted string opener.
    #[test]
    fn apostrophe_in_unquoted_meta_does_not_open_string_mode() {
        let body = r#"
            rule ApostropheMeta {
                meta:
                    author = O'Donnell
                keywords:
                    $x = "x"
                condition:
                    keywords.$x
            }
        "#;
        let rules = parse_rules(body).unwrap();
        assert_eq!(rules[0].meta["author"], "O'Donnell");
    }

    /// Contract: parser accepts a multi-rule file in source order,
    /// matching the upstream NOVA convention. The DSL is line-oriented
    /// (upstream walks `for line in lines[1:]:`) so each section
    /// header / pattern definition / condition lives on its own line.
    #[test]
    fn parses_multiple_rules_in_source_order() {
        let body = r#"
rule First {
    keywords:
        $a = "x"
    condition:
        keywords.$a
}
rule Second {
    keywords:
        $b = "y"
    condition:
        keywords.$b
}
"#;
        let rules = parse_rules(body).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].name, "First");
        assert_eq!(rules[1].name, "Second");
    }

    /// Contract: every published `.nov` file in the canonical NOVA
    /// rule pack parses without error. Pinned against the snapshot
    /// at commit `9249cf49…` cached locally during dev. The
    /// `nova_real_corpus` integration test re-runs this against the
    /// installed pack under `NOVA_RULES_DIR` when that env var is set.
    #[test]
    fn parser_accepts_real_nova_rule_pack_subset() {
        // Hand-pasted minimal rules that exercise every section
        // shape we observed in the v9249cf49 snapshot.
        let bodies = [
            include_str!("test_fixtures/jailbreak_subset.nov"),
            include_str!("test_fixtures/keywords_only.nov"),
            include_str!("test_fixtures/semantics_and_llm.nov"),
            include_str!("test_fixtures/vendor_host.nov"),
        ];
        for body in bodies {
            parse_rules(body).unwrap_or_else(|e| {
                panic!("real-world fixture failed to parse: {e}\n--- body ---\n{body}")
            });
        }
    }

    /// Contract: a regex keyword value with no body between its delimiters
    /// (`/`, `/i`) is rejected as malformed, never panics. The slice
    /// `value[1..closing]` would otherwise hit `begin > end` for `closing == 0`.
    #[test]
    fn keyword_regex_without_body_is_malformed_not_panic() {
        for bad in ["/", "/i"] {
            match parse_keyword_value(bad) {
                Err(ParseError::MalformedLine { .. }) => {}
                other => panic!("{bad:?} should be MalformedLine, got {other:?}"),
            }
        }
    }

    /// Contract: keyword regexes default to case-INSENSITIVE, matching
    /// upstream NOVA. Both the bare `/abc/` and the explicit `/abc/i` forms
    /// yield `case_sensitive == false`; the suffix is stripped from the body
    /// either way.
    #[test]
    fn keyword_regex_with_body_parses_case_insensitive() {
        let bare = parse_keyword_value("/abc/").unwrap();
        assert!(bare.is_regex && !bare.case_sensitive && bare.pattern == "abc");
        let explicit = parse_keyword_value("/abc/i").unwrap();
        assert!(explicit.is_regex && !explicit.case_sensitive && explicit.pattern == "abc");
        // `//` and `//i` are empty (body-present, length 0) regexes — valid.
        assert!(parse_keyword_value("//").unwrap().pattern.is_empty());
        assert!(parse_keyword_value("//i").unwrap().pattern.is_empty());
    }

    /// Contract: one malformed rule line surfaces as a parse error, never a
    /// panic that would abort the whole scan (mirrors the per-rule
    /// "a single bad pattern cannot crash a scan" guarantee).
    #[test]
    fn body_less_regex_in_rule_is_error_not_panic() {
        // The trailing `$y = /a/` supplies a later closing slash so the brace
        // matcher succeeds and `$x = /i` actually reaches `parse_keyword_value`
        // (the panic site under the pre-fix code).
        let body = r#"
            rule Boom {
                keywords:
                    $x = /i
                    $y = /a/
                condition:
                    keywords.$x
            }
        "#;
        assert!(parse_rules(body).is_err());
    }
}
