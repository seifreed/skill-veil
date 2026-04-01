use std::path::{Path, PathBuf};

const SCRIPT_EXT_PATTERN: &str = "sh|py|ps1|js|ts|rb|pl";
const ALL_EXT_PATTERN: &str = "sh|py|ps1|js|ts|rb|pl|exe|bin|dll";

pub(super) fn extract_references(content: &str, base_path: &Path) -> Vec<PathBuf> {
    let mut references = Vec::new();
    let base_dir = base_path.parent().unwrap_or(Path::new("."));

    let link_pattern = format!(r#"\[.*?\]\((\.?/?[^\)]+\.({}))\)"#, ALL_EXT_PATTERN);
    let command_pattern = format!(
        r#"(?:source|run|execute|include)\s+[\"']?([^\s\"']+\.({}))"#,
        SCRIPT_EXT_PATTERN
    );
    let exec_pattern = r#"(?:chmod\s+\+x\s+|\./)([^\s]+)"#;
    let patterns = [
        link_pattern.as_str(),
        command_pattern.as_str(),
        exec_pattern,
    ];

    for pattern in &patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            for cap in re.captures_iter(content) {
                if let Some(m) = cap.get(1) {
                    let file_path = base_dir.join(m.as_str());
                    if !references.contains(&file_path) {
                        references.push(file_path);
                    }
                }
            }
        }
    }

    references
}
