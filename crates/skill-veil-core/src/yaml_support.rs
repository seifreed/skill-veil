use serde::de::DeserializeOwned;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
struct YamlScope {
    indent: usize,
    keys: HashMap<String, usize>,
}

fn extract_yaml_key(line: &str) -> Option<(String, usize)> {
    if line.starts_with('{') || line.starts_with('[') {
        return None;
    }

    let mut in_single = false;
    let mut in_double = false;
    for (index, ch) in line.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            ':' if !in_single && !in_double => {
                let key = line[..index].trim();
                if key.is_empty()
                    || key.starts_with('-')
                    || key.starts_with('&')
                    || key.starts_with('*')
                {
                    return None;
                }
                return Some((
                    key.trim_matches('"').trim_matches('\'').to_string(),
                    index + 1,
                ));
            }
            _ => {}
        }
    }

    None
}

pub fn detect_duplicate_yaml_key(content: &str) -> Option<String> {
    let mut scopes = vec![YamlScope {
        indent: 0,
        keys: HashMap::new(),
    }];

    for (line_index, raw_line) in content.lines().enumerate() {
        let line_number = line_index + 1;
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let indent = raw_line.chars().take_while(|ch| *ch == ' ').count();
        while scopes.len() > 1 && scopes.last().is_some_and(|scope| indent < scope.indent) {
            scopes.pop();
        }

        let key_line = if let Some(rest) = raw_line[indent..].strip_prefix("- ") {
            rest.trim_start()
        } else {
            &raw_line[indent..]
        };

        let scope_indent = if raw_line[indent..].starts_with("- ") {
            indent + 2
        } else {
            indent
        };

        if scopes
            .last()
            .is_none_or(|scope| scope.indent != scope_indent)
        {
            scopes.push(YamlScope {
                indent: scope_indent,
                keys: HashMap::new(),
            });
        }

        let Some((key, column)) = extract_yaml_key(key_line) else {
            continue;
        };

        let scope = scopes.last_mut().expect("scope stack is never empty");
        if let Some(previous_line) = scope.keys.insert(key.clone(), line_number) {
            return Some(format!(
                "duplicate YAML key '{key}' at line {line_number}, column {} (previously defined at line {previous_line})",
                indent + column
            ));
        }
    }

    None
}

fn format_yaml_error(label: &str, error: serde_yaml::Error) -> String {
    if let Some(location) = error.location() {
        format!(
            "{label} YAML parse error at line {}, column {}: {}",
            location.line(),
            location.column(),
            error
        )
    } else {
        format!("{label} YAML parse error: {error}")
    }
}

pub fn parse_yaml_typed<T>(content: &str, label: &str) -> Result<T, String>
where
    T: DeserializeOwned,
{
    if let Some(duplicate_error) = detect_duplicate_yaml_key(content) {
        return Err(format!("{label} {duplicate_error}"));
    }

    let deserializer = serde_yaml::Deserializer::from_str(content);
    match serde_path_to_error::deserialize(deserializer) {
        Ok(value) => Ok(value),
        Err(error) => {
            let path = error.path().to_string();
            let inner = error.into_inner();
            if path.is_empty() {
                Err(format_yaml_error(label, inner))
            } else {
                Err(format!("{} at {}", format_yaml_error(label, inner), path))
            }
        }
    }
}

pub fn parse_json_or_yaml_typed<T>(content: &str, label: &str) -> Result<T, String>
where
    T: DeserializeOwned,
{
    match serde_json::from_str(content) {
        Ok(value) => Ok(value),
        Err(json_error) => parse_yaml_typed(content, label)
            .map_err(|yaml_error| format!("{label} JSON parse error: {json_error}; {yaml_error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_duplicate_yaml_keys_with_line_information() {
        let content = "schema_version: v1\nmetadata:\n  name: a\n  name: b\n";
        let error = parse_yaml_typed::<serde_yaml::Value>(content, "test yaml").unwrap_err();
        assert!(error.contains("duplicate YAML key 'name'"));
        assert!(error.contains("line 4"));
    }
}
