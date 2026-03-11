//! Markdown parser implementation using pulldown-cmark

use crate::analyzer::{CodeBlock, Section};
use crate::ports::{MarkdownParser, ParserError};
use pulldown_cmark::{Event, HeadingLevel, Parser, Tag, TagEnd};

/// Markdown parser implementation using the pulldown-cmark library
#[derive(Debug, Default, Clone)]
pub struct PulldownMarkdownParser;

impl PulldownMarkdownParser {
    /// Create a new pulldown-cmark based parser
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl MarkdownParser for PulldownMarkdownParser {
    fn parse_sections(&self, content: &str) -> Result<Vec<Section>, ParserError> {
        let parser = Parser::new(content);
        let mut sections = Vec::new();
        let mut current_section: Option<Section> = None;
        let mut current_content = String::new();
        let mut in_code_block = false;
        let mut current_code_language: Option<String> = None;
        let mut current_code = String::new();
        let mut code_blocks: Vec<CodeBlock> = Vec::new();

        for event in parser {
            match event {
                Event::Start(Tag::Heading { level, .. }) => {
                    // Save previous section if exists
                    if let Some(mut section) = current_section.take() {
                        section.content = current_content.trim().to_string();
                        section.code_blocks = code_blocks.clone();
                        sections.push(section);
                    }
                    current_content.clear();
                    code_blocks.clear();

                    let level_num = match level {
                        HeadingLevel::H1 => 1,
                        HeadingLevel::H2 => 2,
                        HeadingLevel::H3 => 3,
                        HeadingLevel::H4 => 4,
                        HeadingLevel::H5 => 5,
                        HeadingLevel::H6 => 6,
                    };

                    current_section = Some(Section {
                        name: String::new(),
                        level: level_num,
                        content: String::new(),
                        code_blocks: Vec::new(),
                    });
                }
                Event::End(TagEnd::Heading(_)) => {
                    if let Some(ref mut section) = current_section {
                        section.name = current_content.trim().to_lowercase();
                        current_content.clear();
                    }
                }
                Event::Start(Tag::CodeBlock(kind)) => {
                    in_code_block = true;
                    current_code_language = match kind {
                        pulldown_cmark::CodeBlockKind::Fenced(lang) => {
                            let lang = lang.to_string();
                            if lang.is_empty() {
                                None
                            } else {
                                Some(lang)
                            }
                        }
                        pulldown_cmark::CodeBlockKind::Indented => None,
                    };
                    current_code.clear();
                }
                Event::End(TagEnd::CodeBlock) => {
                    in_code_block = false;
                    code_blocks.push(CodeBlock {
                        language: current_code_language.take(),
                        code: current_code.clone(),
                    });
                    current_content.push_str(&current_code);
                    current_code.clear();
                }
                Event::Text(text) | Event::Code(text) => {
                    if in_code_block {
                        current_code.push_str(&text);
                    } else {
                        current_content.push_str(&text);
                    }
                }
                Event::SoftBreak | Event::HardBreak => {
                    if in_code_block {
                        current_code.push('\n');
                    } else {
                        current_content.push(' ');
                    }
                }
                _ => {}
            }
        }

        // Don't forget the last section
        if let Some(mut section) = current_section.take() {
            section.content = current_content.trim().to_string();
            section.code_blocks = code_blocks;
            sections.push(section);
        }

        Ok(sections)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_markdown() {
        let parser = PulldownMarkdownParser::new();
        let content = r#"# My Skill

## Description
This is a test skill.

## Setup
```bash
echo "hello"
```
"#;

        let sections = parser.parse_sections(content).unwrap();
        assert_eq!(sections.len(), 3);
        assert_eq!(sections[0].name, "my skill");
        assert_eq!(sections[1].name, "description");
        assert_eq!(sections[2].name, "setup");
        assert_eq!(sections[2].code_blocks.len(), 1);
        assert_eq!(sections[2].code_blocks[0].language.as_deref(), Some("bash"));
    }

    #[test]
    fn test_parse_empty_content() {
        let parser = PulldownMarkdownParser::new();
        let sections = parser.parse_sections("").unwrap();
        assert!(sections.is_empty());
    }
}
