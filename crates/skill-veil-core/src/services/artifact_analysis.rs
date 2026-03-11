//! Artifact analysis service for manifests and referenced files.

use crate::artifact_graph::{
    ArtifactCapability, ArtifactCapabilityFact, ArtifactCapabilitySource, ArtifactRelation,
};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity,
    ThreatCategory,
};
use serde_json::Value;
use regex::Regex;
use std::path::{Path, PathBuf};
use toml::Value as TomlValue;

fn extract_http_urls(content: &str) -> Vec<String> {
    let regex = Regex::new(r#"https?://[^\s"'`)]+"#).expect("valid url regex");
    regex
        .find_iter(content)
        .map(|m| m.as_str().trim_end_matches(&['"', '\'', ')'][..]).to_string())
        .collect()
}

fn is_common_lockfile_source(url: &str) -> bool {
    [
        "registry.npmjs.org",
        "registry.yarnpkg.com",
        "repo.yarnpkg.com",
        "mirrors.tencentyun.com",
        "registry.npmmirror.com",
        "registry.yarnpkg.cn",
    ]
    .iter()
    .any(|host| url.contains(host))
}

fn contains_internal_network_target(content: &str) -> Option<&'static str> {
    let lower = content.to_ascii_lowercase();
    if lower.contains("169.254.169.254") {
        Some("169.254.169.254")
    } else if lower.contains("127.0.0.1") {
        Some("127.0.0.1")
    } else if lower.contains("localhost") {
        Some("localhost")
    } else if lower.contains("0.0.0.0") {
        Some("0.0.0.0")
    } else if Regex::new(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
        .expect("valid regex")
        .is_match(&lower)
    {
        Some("rfc1918:10/8")
    } else if Regex::new(r"\b192\.168\.\d{1,3}\.\d{1,3}\b")
        .expect("valid regex")
        .is_match(&lower)
    {
        Some("rfc1918:192.168/16")
    } else if Regex::new(r"\b172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b")
        .expect("valid regex")
        .is_match(&lower)
    {
        Some("rfc1918:172.16/12")
    } else if lower.contains(".internal") {
        Some(".internal")
    } else if lower.contains(".local") {
        Some(".local")
    } else {
        None
    }
}

fn contains_internal_network_action(content: &str) -> bool {
    Regex::new(
        r#"(?is)(curl|wget|fetch|requests\.(get|post)|axios\.(get|post)|invoke-webrequest|invoke-restmethod|httpx\.(get|post)|aiohttp|net/http|client\.get|client\.post|open websocket|connect to|proxy to|query|call|POST|GET).{0,180}(169\.254\.169\.254|127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|\.internal|\.local)"#,
    )
    .expect("valid regex")
    .is_match(content)
}

fn looks_like_local_dev_reference(content: &str) -> bool {
    Regex::new(
        r#"(?i)(local development|for local dev|development server|run locally|example endpoint|sample endpoint|localhost for testing|dev server)"#,
    )
    .expect("valid regex")
    .is_match(content)
}

fn looks_like_local_control_plane_reference(content: &str) -> bool {
    Regex::new(
        r#"(?i)(dashboard|reload|register|heartbeat|local service|local api|development server|run locally|browser open http://localhost|http://localhost:\d+|serve_forever|httpserver)"#,
    )
    .expect("valid regex")
    .is_match(content)
}

fn looks_like_optional_webhook_docs(content: &str) -> bool {
    Regex::new(
        r#"(?is)(alternative:\s*webhook|see\s+/docs/webhooks|for details|if your agent has a publicly reachable endpoint|optional webhook|want real-time push notifications|fallback|polling system|no exposed ip needed|architecture)"#,
    )
    .expect("valid regex")
    .is_match(content)
}

fn looks_like_webhook_receiver_without_auth(content: &str) -> Option<&'static str> {
    let lower = content.to_ascii_lowercase();
    if lower.contains("skip signature validation")
        || lower.contains("no verification required")
        || lower.contains("accept any payload")
        || lower.contains("unsigned webhook")
        || lower.contains("without auth")
    {
        Some("webhook_auth_bypass")
    } else if lower.contains("webhook")
        && (lower.contains("listener")
            || lower.contains("receiver")
            || lower.contains("inbound")
            || lower.contains("callback endpoint")
            || lower.contains("listen on all interfaces")
            || lower.contains("post /api/webhook"))
        && (lower.contains("public endpoint")
            || lower.contains("publicly reachable")
            || lower.contains("0.0.0.0")
            || lower.contains("accept callbacks")
            || lower.contains("incoming webhooks"))
        && !(lower.contains("verify signature")
            || lower.contains("signature verification")
            || lower.contains("hmac")
            || lower.contains("shared secret")
            || lower.contains("signing secret")
            || lower.contains("webhook secret")
            || lower.contains("validate signature"))
        && !looks_like_optional_webhook_docs(content)
        && !Regex::new(r#"(?i)(example webhook|sample webhook|documentation only|for testing only)"#)
            .expect("valid regex")
            .is_match(content)
    {
        Some("public_inbound_endpoint")
    } else {
        None
    }
}

fn contains_ssrf_like_fetch_line(content: &str) -> bool {
    let regex = Regex::new(
        r#"(?i)(curl|wget|fetch|requests\.(get|post)|axios\.(get|post)|invoke-webrequest|invoke-restmethod|httpx\.(get|post)|aiohttp|client\.get|client\.post).{0,180}(169\.254\.169\.254|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|[A-Za-z0-9._-]+\.internal|[A-Za-z0-9._-]+\.local)"#,
    )
    .expect("valid regex");
    content.lines().any(|line| regex.is_match(line))
}

fn permission_context(content: &str) -> String {
    let mut buffer = String::new();
    let lines: Vec<_> = content.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("permission")
            || lower.contains("capabilit")
            || lower.starts_with("- ")
            || lower.starts_with("* ")
        {
            let start = index.saturating_sub(1);
            let end = (index + 3).min(lines.len());
            for snippet in &lines[start..end] {
                buffer.push_str(snippet);
                buffer.push('\n');
            }
        }
    }
    if buffer.is_empty() {
        content.to_string()
    } else {
        buffer
    }
}

fn intent_context(content: &str) -> String {
    let mut buffer = String::new();
    let lines: Vec<_> = content.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("intent")
            || lower.contains("goal")
            || lower.contains("purpose")
            || lower.contains("summary")
            || lower.contains("workflow")
        {
            let start = index;
            let end = (index + 4).min(lines.len());
            for snippet in &lines[start..end] {
                buffer.push_str(snippet);
                buffer.push('\n');
            }
        }
    }
    if buffer.is_empty() {
        content.to_string()
    } else {
        buffer
    }
}

fn explicit_declared_permission_rules(
    content: &str,
) -> Vec<(&'static str, &'static str, &'static str)> {
    let context = permission_context(content).to_ascii_lowercase();
    let mut rules = Vec::new();

    if context.contains("browser: full")
        || context.contains("full autonomous browser")
        || context.contains("allow-all browser")
        || context.contains("click any element")
    {
        rules.push((
            "DECLARED_PERMISSION_BROWSER_FULL",
            "browser full",
            "Artifact declares broad browser automation permissions",
        ));
    }
    if context.contains("write file")
        || context.contains("write files")
        || context.contains("modify files")
        || context.contains("delete work")
        || context.contains("filesystem write")
        || context.contains("file write")
    {
        rules.push((
            "DECLARED_PERMISSION_FILE_WRITE",
            "file write",
            "Artifact declares file modification capabilities",
        ));
    }
    if context.contains("shell exec")
        || context.contains("shell access")
        || context.contains("command execution")
        || context.contains("run commands")
        || context.contains("stdio")
    {
        rules.push((
            "DECLARED_PERMISSION_SHELL_EXEC",
            "shell exec",
            "Artifact declares shell or command execution access",
        ));
    }
    if context.contains("network access")
        || context.contains("external api")
        || context.contains("outbound request")
        || context.contains("webhook access")
        || context.contains("https://")
        || context.contains("http://")
    {
        rules.push((
            "DECLARED_PERMISSION_NETWORK_ACCESS",
            "network access",
            "Artifact declares outbound network access",
        ));
    }
    if context.contains("secret access")
        || context.contains("token access")
        || context.contains("cookie access")
        || context.contains("credentials")
        || context.contains("password")
        || context.contains("secrets store")
        || context.contains("api token")
    {
        rules.push((
            "DECLARED_PERMISSION_SECRETS_ACCESS",
            "secrets access",
            "Artifact declares access to secrets, tokens, cookies, or credentials",
        ));
    }
    if context.contains("oauth")
        || context.contains("scopes")
        || context.contains("calendar")
        || context.contains("drive")
        || context.contains("slack")
        || context.contains("github")
        || context.contains("repo")
    {
        rules.push((
            "DECLARED_PERMISSION_OAUTH_SCOPES",
            "oauth scopes",
            "Artifact declares OAuth scopes or identity-linked access",
        ));
    }

    rules
}

fn infer_declared_intent(content: &str) -> (&'static str, usize) {
    let lower = intent_context(content).to_ascii_lowercase();
    let narrow = [
        "read-only",
        "summarize",
        "status",
        "audit",
        "inspect",
        "view only",
        "list only",
        "review",
        "report",
        "observe",
    ]
    .into_iter()
    .filter(|needle| lower.contains(needle))
    .count();
    let mutating = [
        "delete",
        "modify",
        "write",
        "merge",
        "submit",
        "apply changes",
        "execute",
        "run command",
        "post data",
        "send",
    ]
    .into_iter()
    .filter(|needle| lower.contains(needle))
    .count();

    if narrow > 0 && mutating == 0 {
        ("narrow", narrow)
    } else if mutating > 0 {
        ("broad", mutating)
    } else {
        ("unknown", 0)
    }
}

fn is_opaque_mcp_endpoint(content: &str) -> bool {
    Regex::new("(?i)(ngrok|trycloudflare|workers\\.dev|raw\\.githubusercontent\\.com|pastebin\\.com)")
        .expect("valid regex")
        .is_match(content)
}

fn mcp_declares_no_auth(content: &str) -> bool {
    Regex::new("(?is)(\"auth\"\\s*:\\s*\"none\"|authentication\\s*:\\s*none|no auth|without auth|auth\\s*:\\s*none)")
        .expect("valid regex")
        .is_match(content)
}

fn mcp_declares_inline_secret(content: &str) -> bool {
    Regex::new("(?is)(bearer\\s+[A-Za-z0-9._-]{8,}|authorization\\s*:\\s*bearer|api[_-]?key|_authtoken=|token\\s*[:=]\\s*[A-Za-z0-9._-]{8,})")
        .expect("valid regex")
        .is_match(content)
}

fn mcp_declares_permissive_tools(content: &str) -> bool {
    Regex::new("(?is)(\"tools\"\\s*:\\s*\\[[^\\]]*\"\\*\"|allow_all_tools|all_tools|tool_permissions\\s*:\\s*\"all\"|expose all tools)")
        .expect("valid regex")
        .is_match(content)
}

fn extract_mcp_tool_names(content: &str) -> Vec<String> {
    let mut tools = Vec::new();
    let quoted_tool = Regex::new(r#""([A-Za-z0-9._:-]{2,})""#).expect("valid regex");
    if let Some(array_match) = Regex::new(r#"(?is)"tools"\s*:\s*\[([^\]]+)\]"#)
        .expect("valid regex")
        .captures(content)
        .and_then(|captures| captures.get(1))
    {
        for capture in quoted_tool.captures_iter(array_match.as_str()) {
            if let Some(name) = capture.get(1) {
                let value = name.as_str().to_string();
                if !tools.contains(&value) {
                    tools.push(value);
                }
            }
        }
    }
    tools
}

pub struct ArtifactAnalysisService;

#[derive(Debug, Clone)]
pub struct ArtifactLink {
    pub target: String,
    pub relation: ArtifactRelation,
}

impl ArtifactAnalysisService {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, path: &Path, content: &str, sibling_files: &[PathBuf]) -> Vec<Finding> {
        let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
            return Vec::new();
        };

        match file_name.to_ascii_lowercase().as_str() {
            "package.json" => self.analyze_package_json(path, content, sibling_files),
            "mcp.json" | "mcp.yaml" | "mcp.yml" => self.analyze_mcp_manifest(path, content),
            "skill.md" => self.analyze_skill_document(path, content),
            "requirements.txt" => self.analyze_requirements_txt(path, content, sibling_files),
            "pyproject.toml" => self.analyze_pyproject_toml(path, content, sibling_files),
            "cargo.toml" => self.analyze_cargo_toml(path, content, sibling_files),
            "package-lock.json" => self.analyze_package_lock(path, content),
            "cargo.lock" => self.analyze_cargo_lock(path, content),
            "poetry.lock" => self.analyze_poetry_lock(path, content),
            "uv.lock" => self.analyze_uv_lock(path, content),
            "yarn.lock" => self.analyze_yarn_lock(path, content),
            "pnpm-lock.yaml" => self.analyze_pnpm_lock(path, content),
            "dockerfile" => self.analyze_dockerfile(path, content),
            "docker-compose.yml" | "docker-compose.yaml" => {
                self.analyze_docker_compose(path, content)
            }
            "makefile" => self.analyze_makefile(path, content),
            ".npmrc" => self.analyze_npmrc(path, content),
            "pip.conf" => self.analyze_pip_conf(path, content),
            "agents.md" | "claude.md" | "system.md" | "persona.md" | "soul.md" => {
                self.analyze_instruction_file(path, content)
            }
            _ if file_name.to_ascii_lowercase().ends_with(".skill.md") => {
                self.analyze_skill_document(path, content)
            }
            _ if Self::is_prompt_pack_document(path) => self.analyze_prompt_pack(path, content),
            _ if Self::looks_like_script(path) => self.analyze_script(path, content),
            _ => Vec::new(),
        }
    }

    pub fn infer_relations(&self, path: &Path, content: &str) -> Vec<ArtifactLink> {
        let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
            return Vec::new();
        };

        match file_name.to_ascii_lowercase().as_str() {
            "mcp.json" | "mcp.yaml" | "mcp.yml" => self.mcp_manifest_relations(content),
            "docker-compose.yml" | "docker-compose.yaml" => self.docker_compose_relations(content),
            "dockerfile" => self.dockerfile_relations(content),
            "package.json" => self.package_json_relations(content),
            "package-lock.json" | "cargo.lock" | "poetry.lock" | "uv.lock" | "yarn.lock"
            | "pnpm-lock.yaml" => self.lockfile_relations(content),
            "makefile" => self.makefile_relations(content),
            ".npmrc" => self.npmrc_relations(content),
            "pip.conf" => self.pip_conf_relations(content),
            "agents.md" | "claude.md" | "system.md" | "persona.md" | "soul.md" => {
                self.instruction_relations(content)
            }
            _ if Self::is_prompt_pack_document(path) => self.instruction_relations(content),
            _ if Self::looks_like_script(path) => self.script_relations(content),
            _ => Vec::new(),
        }
    }

    pub fn infer_capabilities(&self, path: &Path, content: &str) -> Vec<ArtifactCapabilityFact> {
        let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
            return Vec::new();
        };

        match file_name.to_ascii_lowercase().as_str() {
            "package.json" => self.package_json_capabilities(content),
            "mcp.json" | "mcp.yaml" | "mcp.yml" => self.mcp_manifest_capabilities(content),
            "dockerfile" => self.dockerfile_capabilities(content),
            "docker-compose.yml" | "docker-compose.yaml" => {
                self.docker_compose_capabilities(content)
            }
            "makefile" => self.makefile_capabilities(content),
            ".npmrc" => self.npmrc_capabilities(content),
            "pip.conf" => self.pip_conf_capabilities(content),
            "agents.md" | "claude.md" | "system.md" | "persona.md" | "soul.md" => {
                self.instruction_capabilities(content)
            }
            _ if Self::is_prompt_pack_document(path) => self.instruction_capabilities(content),
            "package-lock.json" | "cargo.lock" | "poetry.lock" | "uv.lock" | "yarn.lock"
            | "pnpm-lock.yaml" => self.lockfile_capabilities(content),
            _ if Self::looks_like_script(path) => self.script_capabilities(content),
            _ => Vec::new(),
        }
    }

    pub fn expected_lockfiles(&self, path: &Path, content: &str) -> Vec<&'static str> {
        let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
            return Vec::new();
        };

        match file_name.to_ascii_lowercase().as_str() {
            "package.json" => self.package_json_expected_lockfiles(content),
            "pyproject.toml" => self.pyproject_expected_lockfiles(content),
            "cargo.toml" => vec!["Cargo.lock"],
            _ => Vec::new(),
        }
    }

    fn is_prompt_pack_document(path: &Path) -> bool {
        path.file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| name.to_ascii_lowercase().ends_with(".prompt.md"))
            || path
                .parent()
                .and_then(|parent| parent.file_name())
                .and_then(|value| value.to_str())
                .is_some_and(|name| name.eq_ignore_ascii_case("prompts"))
    }

    fn analyze_instruction_file(&self, path: &Path, content: &str) -> Vec<Finding> {
        let mut findings =
            self.semantic_persistence_findings(path, content, ArtifactKind::AgentInstruction);
        findings.extend(self.permission_and_network_findings(
            path,
            content,
            ArtifactKind::AgentInstruction,
        ));
        findings
    }

    fn analyze_skill_document(&self, path: &Path, content: &str) -> Vec<Finding> {
        let mut findings =
            self.semantic_persistence_findings(path, content, ArtifactKind::SkillDocument);
        findings.extend(self.permission_and_network_findings(
            path,
            content,
            ArtifactKind::SkillDocument,
        ));
        findings
    }

    fn analyze_prompt_pack(&self, path: &Path, content: &str) -> Vec<Finding> {
        let mut findings =
            self.semantic_persistence_findings(path, content, ArtifactKind::PromptPackDocument);
        findings.extend(self.permission_and_network_findings(
            path,
            content,
            ArtifactKind::PromptPackDocument,
        ));
        findings
    }

    fn analyze_package_json(&self, path: &Path, content: &str, sibling_files: &[PathBuf]) -> Vec<Finding> {
        let Ok(json) = serde_json::from_str::<Value>(content) else {
            return Vec::new();
        };

        let mut findings = Vec::new();
        let artifact_path = path.display().to_string();

        for dependency_field in ["dependencies", "devDependencies", "optionalDependencies"] {
            let Some(dependencies) = json.get(dependency_field).and_then(Value::as_object) else {
                continue;
            };

            for (name, version) in dependencies {
                let Some(version_str) = version.as_str() else {
                    continue;
                };

                if version_str.starts_with('^')
                    || version_str.starts_with('~')
                    || version_str == "latest"
                    || version_str == "*"
                {
                    findings.push(
                        Finding::builder(
                            "MANIFEST_PACKAGE_JSON_UNPINNED_DEP",
                            ThreatCategory::SupplyChain,
                        )
                        .severity(Severity::Low)
                        .action(RecommendedAction::Log)
                        .evidence_kind(EvidenceKind::Context)
                        .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                        .matched_on(MatchTarget::ReferencedFile {
                            path: artifact_path.clone(),
                        })
                        .match_value(format!("{name}@{version_str}"))
                        .reason("Manifest dependency is not strictly pinned")
                        .build(),
                    );
                }
            }
        }

        if let Some(scripts) = json.get("scripts").and_then(Value::as_object) {
            for hook in ["preinstall", "install", "postinstall"] {
                if let Some(command) = scripts.get(hook).and_then(Value::as_str) {
                    let lower_command = command.to_ascii_lowercase();
                    let risky_install_hook = [
                        "curl ",
                        "wget ",
                        "http://",
                        "https://",
                        "powershell",
                        "invoke-webrequest",
                        "iwr ",
                        "bash -c",
                        "sh -c",
                        "python -c",
                        "node -e",
                    ]
                    .iter()
                    .any(|needle| lower_command.contains(needle));
                    findings.push(
                        Finding::builder(
                            "MANIFEST_PACKAGE_JSON_INSTALL_HOOK",
                            ThreatCategory::SupplyChain,
                        )
                        .severity(if risky_install_hook {
                            Severity::Medium
                        } else {
                            Severity::Low
                        })
                        .action(if risky_install_hook {
                            RecommendedAction::RequireApproval
                        } else {
                            RecommendedAction::Log
                        })
                        .evidence_kind(if risky_install_hook {
                            EvidenceKind::Behavior
                        } else {
                            EvidenceKind::Context
                        })
                        .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                        .matched_on(MatchTarget::ReferencedFile {
                            path: artifact_path.clone(),
                        })
                        .match_value(format!("{hook}: {command}"))
                        .reason(if risky_install_hook {
                            "Manifest defines an install lifecycle hook that fetches or executes code"
                        } else {
                            "Manifest defines an install lifecycle hook"
                        })
                        .build(),
                    );
                }
            }
        }

        if json.get("bin").is_some() {
            findings.push(
                Finding::builder("MANIFEST_PACKAGE_JSON_BIN_EXPOSED", ThreatCategory::ScopeCreep)
                    .severity(Severity::Low)
                    .action(RecommendedAction::Log)
                    .evidence_kind(EvidenceKind::Context)
                    .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value("bin")
                    .reason("Manifest exposes executable binaries")
                    .build(),
            );
        }

        let expected_lockfiles = self.package_json_expected_lockfiles(content);
        if !expected_lockfiles.is_empty() {
            findings.extend(self.missing_lockfile_findings(
                path,
                sibling_files,
                &expected_lockfiles,
                "MANIFEST_PACKAGE_JSON_MISSING_LOCKFILE",
                "JavaScript manifest has no matching nearby lockfile",
            ));
        }

        findings
    }

    fn analyze_requirements_txt(
        &self,
        path: &Path,
        content: &str,
        _sibling_files: &[PathBuf],
    ) -> Vec<Finding> {
        let artifact_path = path.display().to_string();
        let findings: Vec<_> = content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter(|line| !line.starts_with("-r ") && !line.starts_with("--requirement"))
            .filter(|line| !line.contains("=="))
            .map(|line| {
                Finding::builder("MANIFEST_REQUIREMENTS_UNPINNED_DEP", ThreatCategory::SupplyChain)
                    .severity(Severity::Low)
                    .action(RecommendedAction::Log)
                    .evidence_kind(EvidenceKind::Context)
                    .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value(line)
                    .reason("Python requirement is not strictly pinned")
                    .build()
            })
            .collect();

        findings
    }

    fn analyze_dockerfile(&self, path: &Path, content: &str) -> Vec<Finding> {
        let artifact_path = path.display().to_string();
        let mut findings = Vec::new();

        for line in content.lines().map(str::trim) {
            if line.to_ascii_lowercase().starts_with("from ") && line.ends_with(":latest") {
                findings.push(
                    Finding::builder("MANIFEST_DOCKER_LATEST_TAG", ThreatCategory::SupplyChain)
                        .severity(Severity::Low)
                        .action(RecommendedAction::RequireApproval)
                        .evidence_kind(EvidenceKind::Context)
                        .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                        .matched_on(MatchTarget::ReferencedFile {
                            path: artifact_path.clone(),
                        })
                        .match_value(line)
                        .reason("Docker base image uses the mutable latest tag")
                        .build(),
                );
            }
        }

        findings
    }

    fn analyze_pyproject_toml(&self, path: &Path, content: &str, sibling_files: &[PathBuf]) -> Vec<Finding> {
        let Ok(toml) = content.parse::<TomlValue>() else {
            return Vec::new();
        };

        let artifact_path = path.display().to_string();
        let mut findings = Vec::new();

        if let Some(dependencies) = toml
            .get("project")
            .and_then(|project| project.get("dependencies"))
            .and_then(TomlValue::as_array)
        {
            for dependency in dependencies.iter().filter_map(TomlValue::as_str) {
                if !(dependency.contains("==") || dependency.contains("@")) {
                    findings.push(
                        Finding::builder("MANIFEST_PYPROJECT_UNPINNED_DEP", ThreatCategory::SupplyChain)
                            .severity(Severity::Low)
                            .action(RecommendedAction::RequireApproval)
                            .evidence_kind(EvidenceKind::Context)
                            .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                            .matched_on(MatchTarget::ReferencedFile {
                                path: artifact_path.clone(),
                            })
                            .match_value(dependency)
                            .reason("pyproject dependency is not strictly pinned")
                            .build(),
                    );
                }
            }
        }

        let expected_lockfiles = self.pyproject_expected_lockfiles(content);
        if !expected_lockfiles.is_empty() {
            findings.extend(self.missing_lockfile_findings(
                path,
                sibling_files,
                &expected_lockfiles,
                "MANIFEST_PYPROJECT_MISSING_LOCKFILE",
                "pyproject manifest has no matching nearby lockfile",
            ));
        }

        findings
    }

    fn analyze_cargo_toml(&self, path: &Path, content: &str, sibling_files: &[PathBuf]) -> Vec<Finding> {
        let Ok(toml) = content.parse::<TomlValue>() else {
            return Vec::new();
        };

        let artifact_path = path.display().to_string();
        let mut findings = Vec::new();

        if let Some(dependencies) = toml.get("dependencies").and_then(TomlValue::as_table) {
            for (name, dependency) in dependencies {
                let version = match dependency {
                    TomlValue::String(version) => Some(version.as_str()),
                    TomlValue::Table(table) => table.get("version").and_then(TomlValue::as_str),
                    _ => None,
                };

                if let Some(version) = version {
                    if version.starts_with('^') || version.starts_with('~') || version == "*" {
                        findings.push(
                            Finding::builder("MANIFEST_CARGO_UNPINNED_DEP", ThreatCategory::SupplyChain)
                                .severity(Severity::Low)
                                .action(RecommendedAction::RequireApproval)
                                .evidence_kind(EvidenceKind::Context)
                                .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                                .matched_on(MatchTarget::ReferencedFile {
                                    path: artifact_path.clone(),
                                })
                                .match_value(format!("{name} = {version}"))
                                .reason("Cargo dependency is not strictly pinned")
                                .build(),
                        );
                    }
                }
            }
        }

        findings.extend(self.missing_lockfile_findings(
            path,
            sibling_files,
            &["Cargo.lock"],
            "MANIFEST_CARGO_MISSING_LOCKFILE",
            "Cargo manifest has no matching nearby lockfile",
        ));

        findings
    }

    fn analyze_docker_compose(&self, path: &Path, content: &str) -> Vec<Finding> {
        let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(content) else {
            return Vec::new();
        };

        let artifact_path = path.display().to_string();
        let mut findings = Vec::new();

        let Some(services) = yaml.get("services").and_then(serde_yaml::Value::as_mapping) else {
            return findings;
        };

        for (service_name, service) in services {
            let service_name = service_name.as_str().unwrap_or("unknown");
            let Some(mapping) = service.as_mapping() else {
                continue;
            };

            if let Some(image) = mapping
                .get(serde_yaml::Value::String("image".to_string()))
                .and_then(serde_yaml::Value::as_str)
            {
                if image.ends_with(":latest") {
                    findings.push(
                        Finding::builder(
                            "MANIFEST_DOCKER_COMPOSE_LATEST_TAG",
                            ThreatCategory::SupplyChain,
                        )
                        .severity(Severity::Low)
                        .action(RecommendedAction::RequireApproval)
                        .evidence_kind(EvidenceKind::Context)
                        .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                        .matched_on(MatchTarget::ReferencedFile {
                            path: artifact_path.clone(),
                        })
                        .match_value(format!("{service_name}: {image}"))
                        .reason("docker-compose service uses a mutable latest image tag")
                        .build(),
                    );
                }
            }

            if mapping.contains_key(serde_yaml::Value::String("privileged".to_string()))
                && mapping
                    .get(serde_yaml::Value::String("privileged".to_string()))
                    .and_then(serde_yaml::Value::as_bool)
                    == Some(true)
            {
                findings.push(
                    Finding::builder(
                        "MANIFEST_DOCKER_COMPOSE_PRIVILEGED",
                        ThreatCategory::PrivilegeEscalation,
                    )
                    .severity(Severity::Medium)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Behavior)
                    .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value(format!("{service_name}: privileged=true"))
                    .reason("docker-compose service requests privileged execution")
                    .build(),
                );
            }

            if let Some(volumes) = mapping
                .get(serde_yaml::Value::String("volumes".to_string()))
                .and_then(serde_yaml::Value::as_sequence)
            {
                for volume in volumes.iter().filter_map(serde_yaml::Value::as_str) {
                    if volume.starts_with("/:") || volume.starts_with("/:/") || volume.contains(":/host") {
                        findings.push(
                            Finding::builder(
                                "MANIFEST_DOCKER_COMPOSE_HOST_MOUNT",
                                ThreatCategory::PrivilegeEscalation,
                            )
                            .severity(Severity::Medium)
                            .action(RecommendedAction::RequireApproval)
                            .evidence_kind(EvidenceKind::Behavior)
                            .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                            .matched_on(MatchTarget::ReferencedFile {
                                path: artifact_path.clone(),
                            })
                            .match_value(format!("{service_name}: {volume}"))
                            .reason("docker-compose service mounts sensitive host paths")
                            .build(),
                        );
                    }
                }
            }

            if let Some(network_mode) = mapping
                .get(serde_yaml::Value::String("network_mode".to_string()))
                .and_then(serde_yaml::Value::as_str)
            {
                if matches!(network_mode, "host" | "service:host") {
                    findings.push(
                        Finding::builder(
                            "MANIFEST_DOCKER_COMPOSE_HOST_NETWORK",
                            ThreatCategory::PrivilegeEscalation,
                        )
                        .severity(Severity::Medium)
                        .action(RecommendedAction::RequireApproval)
                        .evidence_kind(EvidenceKind::Behavior)
                        .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                        .matched_on(MatchTarget::ReferencedFile {
                            path: artifact_path.clone(),
                        })
                        .match_value(format!("{service_name}: network_mode={network_mode}"))
                        .reason("docker-compose service shares the host network namespace")
                        .build(),
                    );
                }
            }

            if let Some(env_file) = mapping.get(serde_yaml::Value::String("env_file".to_string())) {
                findings.push(
                    Finding::builder(
                        "MANIFEST_DOCKER_COMPOSE_ENV_FILE",
                        ThreatCategory::CredentialExposure,
                    )
                    .severity(Severity::Low)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Context)
                    .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value(format!("{service_name}: {:?}", env_file))
                    .reason("docker-compose service loads environment files that may contain secrets")
                    .build(),
                );
            }
        }

        findings
    }

    fn analyze_makefile(&self, path: &Path, content: &str) -> Vec<Finding> {
        let artifact_path = path.display().to_string();
        let mut findings = Vec::new();
        for line in content.lines().map(str::trim) {
            let lower = line.to_ascii_lowercase();
            if lower.contains("curl ") || lower.contains("wget ") {
                findings.push(
                    Finding::builder("MANIFEST_MAKEFILE_REMOTE_DOWNLOAD", ThreatCategory::SupplyChain)
                        .severity(Severity::Medium)
                        .action(RecommendedAction::RequireApproval)
                        .evidence_kind(EvidenceKind::Behavior)
                        .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                        .matched_on(MatchTarget::ReferencedFile { path: artifact_path.clone() })
                        .match_value(line)
                        .reason("Makefile performs remote downloads")
                        .build(),
                );
            }
        }
        findings
    }

    fn analyze_npmrc(&self, path: &Path, content: &str) -> Vec<Finding> {
        let artifact_path = path.display().to_string();
        let mut findings: Vec<_> = content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter(|line| line.to_ascii_lowercase().contains("_authtoken="))
            .map(|line| {
                Finding::builder("MANIFEST_NPMRC_EMBEDDED_TOKEN", ThreatCategory::CredentialExposure)
                    .severity(Severity::High)
                    .action(RecommendedAction::Block)
                    .evidence_kind(EvidenceKind::Behavior)
                    .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile { path: artifact_path.clone() })
                    .match_value(line)
                    .reason("npm configuration embeds an authentication token")
                    .build()
            })
            .collect();

        if content
            .lines()
            .any(|line| line.trim().to_ascii_lowercase().starts_with("registry=http"))
        {
            findings.push(
                Finding::builder("MANIFEST_NPMRC_CUSTOM_REGISTRY", ThreatCategory::SupplyChain)
                    .severity(Severity::Medium)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Context)
                    .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile { path: artifact_path.clone() })
                    .match_value("registry")
                    .reason("npm configuration overrides the default registry")
                    .build(),
            );
        }

        findings
    }

    fn analyze_pip_conf(&self, path: &Path, content: &str) -> Vec<Finding> {
        let artifact_path = path.display().to_string();
        let mut findings: Vec<_> = content
            .lines()
            .map(str::trim)
            .filter(|line| line.to_ascii_lowercase().contains("extra-index-url"))
            .map(|line| {
                Finding::builder("MANIFEST_PIP_CONF_EXTRA_INDEX", ThreatCategory::SupplyChain)
                    .severity(Severity::Medium)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Context)
                    .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile { path: artifact_path.clone() })
                    .match_value(line)
                    .reason("pip configuration adds an extra package index")
                    .build()
            })
            .collect();

        if content
            .lines()
            .any(|line| line.to_ascii_lowercase().contains("trusted-host"))
        {
            findings.push(
                Finding::builder("MANIFEST_PIP_CONF_TRUSTED_HOST", ThreatCategory::SupplyChain)
                    .severity(Severity::Medium)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Context)
                    .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile { path: artifact_path.clone() })
                    .match_value("trusted-host")
                    .reason("pip configuration trusts a custom package host")
                    .build(),
            );
        }

        findings
    }

    fn analyze_script(&self, path: &Path, content: &str) -> Vec<Finding> {
        let artifact_path = path.display().to_string();
        let language = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        let lower = content.to_ascii_lowercase();
        let mut findings = Vec::new();

        let remote_binary_patterns = [
            ("SCRIPT_REMOTE_BINARY_DOWNLOAD", "(?i)(curl|wget).*(\\.sh|\\.ps1|\\.py|\\.js|\\.exe|\\.pkg|\\.dmg|\\.deb|\\.rpm)"),
            ("SCRIPT_POWERSHELL_REMOTE_DOWNLOAD", "(?i)invoke-webrequest.+(\\.ps1|\\.exe|\\.zip)"),
        ];
        for (rule_id, pattern) in remote_binary_patterns {
            let regex = Regex::new(pattern).expect("valid regex");
            for matched in regex.find_iter(content) {
                findings.push(
                    Finding::builder(rule_id, ThreatCategory::SupplyChain)
                        .severity(Severity::High)
                        .action(RecommendedAction::RequireApproval)
                        .evidence_kind(EvidenceKind::Behavior)
                        .artifact(ArtifactKind::ReferencedArtifact, Some(artifact_path.clone()))
                        .matched_on(MatchTarget::ReferencedFile { path: artifact_path.clone() })
                        .match_value(matched.as_str())
                        .reason("Script downloads a remote script or binary payload")
                        .build(),
                );
            }
        }

        let deferred_patterns = [
            ("SCRIPT_DEFERRED_EXECUTION", "(?i)(crontab|schtasks|at\\s+\\d|systemd-run|launchctl\\s+load)"),
            ("SCRIPT_PERSISTENCE", "(?i)(/etc/cron|~/\\.config/autostart|launchagents|startup\\\\|runonce)"),
        ];
        for (rule_id, pattern) in deferred_patterns {
            let regex = Regex::new(pattern).expect("valid regex");
            for matched in regex.find_iter(content) {
                findings.push(
                    Finding::builder(rule_id, ThreatCategory::PrivilegeEscalation)
                        .severity(Severity::Medium)
                        .action(RecommendedAction::RequireApproval)
                        .evidence_kind(EvidenceKind::Behavior)
                        .artifact(ArtifactKind::ReferencedArtifact, Some(artifact_path.clone()))
                        .matched_on(MatchTarget::ReferencedFile { path: artifact_path.clone() })
                        .match_value(matched.as_str())
                        .reason("Script configures deferred execution or persistence")
                        .build(),
                );
            }
        }

        if matches!(language.as_str(), "js" | "ts")
            && (lower.contains("child_process") || lower.contains("exec(") || lower.contains("spawn("))
        {
            let risky_process_exec = [
                "curl ",
                "wget ",
                "http://",
                "https://",
                "bash",
                "sh ",
                "powershell",
                "cmd.exe",
                "invoke-webrequest",
            ]
            .iter()
            .any(|needle| lower.contains(needle));
            findings.push(
                Finding::builder("SCRIPT_NODE_PROCESS_EXEC", ThreatCategory::RemoteExec)
                    .severity(if risky_process_exec {
                        Severity::Medium
                    } else {
                        Severity::Low
                    })
                    .action(if risky_process_exec {
                        RecommendedAction::RequireApproval
                    } else {
                        RecommendedAction::Log
                    })
                    .evidence_kind(if risky_process_exec {
                        EvidenceKind::Behavior
                    } else {
                        EvidenceKind::Context
                    })
                    .artifact(ArtifactKind::ReferencedArtifact, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile { path: artifact_path.clone() })
                    .match_value("child_process")
                    .reason(if risky_process_exec {
                        "Node script spawns subprocesses with shell or network execution semantics"
                    } else {
                        "Node script spawns local subprocesses"
                    })
                    .build(),
            );
        }

        if language == "py"
            && (lower.contains("subprocess.") || lower.contains("os.system(") || lower.contains("requests.get("))
        {
            findings.push(
                Finding::builder("SCRIPT_PYTHON_EXEC_NETWORK", ThreatCategory::RemoteExec)
                    .severity(Severity::Medium)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Behavior)
                    .artifact(ArtifactKind::ReferencedArtifact, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile { path: artifact_path.clone() })
                    .match_value("subprocess/requests")
                    .reason("Python script combines execution or network primitives")
                    .build(),
            );
        }

        if language == "py"
            && (lower.contains("open(\"/etc/")
                || lower.contains("open('/etc/")
                || lower.contains("os.getenv(")
                || lower.contains("pathlib.path.home()")
                || lower.contains("os.environ"))
        {
            findings.push(
                Finding::builder("SCRIPT_PYTHON_SECRET_OR_SYSTEM_ACCESS", ThreatCategory::CredentialExposure)
                    .severity(Severity::Medium)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Behavior)
                    .artifact(ArtifactKind::ReferencedArtifact, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile { path: artifact_path.clone() })
                    .match_value("python secret/system access")
                    .reason("Python script reads environment variables, home paths, or system files")
                    .build(),
            );
        }

        if language == "ps1"
            && (lower.contains("start-process") || lower.contains("invoke-expression") || lower.contains("iex "))
        {
            findings.push(
                Finding::builder("SCRIPT_POWERSHELL_EXEC", ThreatCategory::RemoteExec)
                    .severity(Severity::High)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Behavior)
                    .artifact(ArtifactKind::ReferencedArtifact, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile { path: artifact_path.clone() })
                    .match_value("Start-Process/IEX")
                    .reason("PowerShell script executes commands dynamically")
                    .build(),
            );
        }

        if language == "ps1"
            && (lower.contains("new-itemproperty")
                || lower.contains("set-itemproperty")
                || lower.contains("scheduledtask")
                || lower.contains("register-scheduledtask"))
        {
            findings.push(
                Finding::builder("SCRIPT_POWERSHELL_PERSISTENCE", ThreatCategory::PrivilegeEscalation)
                    .severity(Severity::High)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Behavior)
                    .artifact(ArtifactKind::ReferencedArtifact, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile { path: artifact_path.clone() })
                    .match_value("registry/scheduled task persistence")
                    .reason("PowerShell script configures persistence via registry or scheduled tasks")
                    .build(),
            );
        }

        if matches!(language.as_str(), "sh" | "bash" | "zsh")
            && (lower.contains("chmod +x") || lower.contains("nohup ") || lower.contains("/dev/tcp/"))
        {
            findings.push(
                Finding::builder("SCRIPT_SHELL_INSTALL_SIDE_EFFECT", ThreatCategory::SupplyChain)
                    .severity(Severity::Low)
                    .action(RecommendedAction::Log)
                    .evidence_kind(EvidenceKind::Context)
                    .artifact(ArtifactKind::ReferencedArtifact, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile { path: artifact_path.clone() })
                    .match_value("shell side effects")
                    .reason("Shell script changes execution mode or runs detached install-time commands")
                    .build(),
            );
        }

        if matches!(language.as_str(), "sh" | "bash" | "zsh")
            && (lower.contains("> /etc/")
                || lower.contains("tee /etc/")
                || lower.contains("echo ") && lower.contains(">> ~/."))
        {
            findings.push(
                Finding::builder("SCRIPT_SHELL_PERSISTENCE_WRITE", ThreatCategory::PrivilegeEscalation)
                    .severity(Severity::High)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Behavior)
                    .artifact(ArtifactKind::ReferencedArtifact, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile { path: artifact_path.clone() })
                    .match_value("shell persistence write")
                    .reason("Shell script writes to startup or system configuration paths")
                    .build(),
            );
        }

        if matches!(language.as_str(), "js" | "ts")
            && ((lower.contains("process.env")
                && (lower.contains("token")
                    || lower.contains("secret")
                    || lower.contains("cookie")
                    || lower.contains("session")
                    || lower.contains("auth")))
                || lower.contains("fs.readfilesync(process.env")
                || lower.contains("fs.readfilesync(\"/etc/")
                || lower.contains("fs.readfilesync('/etc/"))
        {
            findings.push(
                Finding::builder("SCRIPT_NODE_SECRET_OR_FS_ACCESS", ThreatCategory::CredentialExposure)
                    .severity(Severity::Medium)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Behavior)
                    .artifact(ArtifactKind::ReferencedArtifact, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile { path: artifact_path.clone() })
                    .match_value("process.env/fs access")
                    .reason("Node script accesses environment variables or sensitive filesystem paths")
                    .build(),
            );
        }

        let shell_injection_patterns = [
            ("COMMAND_INJECTION_SINK_SHELL", r#"(?i)(bash|sh)\s+-c\s+["']?\$[A-Za-z_][A-Za-z0-9_]*"#),
            (
                "UNSAFE_USER_CONTROLLED_EXEC_SHELL",
                r#"(?i)(curl|wget)[^\n]{0,180}(\$[1-9]|\$\{?[A-Za-z_]*(INPUT|USER_INPUT|CMD|COMMAND|ARGS?|REQUEST_URL|TARGET_URL)\}?)"#,
            ),
        ];
        let python_injection_patterns = [
            (
                "COMMAND_INJECTION_SINK_PYTHON",
                r#"(?i)subprocess\.(run|popen|call)\([^)]*shell\s*=\s*true"#,
            ),
            (
                "UNSAFE_USER_CONTROLLED_EXEC_PYTHON",
                r#"(?i)os\.system\(f?["'][^"']*\{[A-Za-z_][A-Za-z0-9_]*\}"#,
            ),
        ];
        let node_injection_patterns = [
            (
                "COMMAND_INJECTION_SINK_NODE",
                r#"(?i)child_process\.(exec|spawn)\([^)]*(req\.|process\.argv|userInput|input|cmd|command)"#,
            ),
            (
                "UNSAFE_USER_CONTROLLED_EXEC_NODE",
                r#"(?i)child_process\.(exec|spawn)\([^)]*(req\.|process\.argv|userInput|input)"#,
            ),
        ];
        let powershell_injection_patterns = [
            (
                "COMMAND_INJECTION_SINK_POWERSHELL",
                r#"(?i)invoke-expression\s+\$[A-Za-z_][A-Za-z0-9_]*"#,
            ),
            (
                "UNSAFE_USER_CONTROLLED_EXEC_POWERSHELL",
                r#"(?i)start-process\s+\$[A-Za-z_][A-Za-z0-9_]*"#,
            ),
        ];

        let patterns = match language.as_str() {
            "sh" | "bash" | "zsh" => &shell_injection_patterns[..],
            "py" => &python_injection_patterns[..],
            "js" | "ts" => &node_injection_patterns[..],
            "ps1" => &powershell_injection_patterns[..],
            _ => &[][..],
        };
        for (rule_id, pattern) in patterns {
            let regex = Regex::new(pattern).expect("valid regex");
            for matched in regex.find_iter(content) {
                findings.push(
                    Finding::builder(*rule_id, ThreatCategory::RemoteExec)
                        .severity(Severity::High)
                        .action(RecommendedAction::RequireApproval)
                        .evidence_kind(EvidenceKind::Behavior)
                        .artifact(ArtifactKind::ReferencedArtifact, Some(artifact_path.clone()))
                        .matched_on(MatchTarget::ReferencedFile { path: artifact_path.clone() })
                        .match_value(matched.as_str())
                        .reason("Script contains an execution sink that appears to be influenced by variable or user-controlled input")
                        .build(),
                );
            }
        }

        findings.extend(self.permission_and_network_findings(
            path,
            content,
            ArtifactKind::ReferencedArtifact,
        ));

        findings
    }

    fn analyze_package_lock(&self, path: &Path, content: &str) -> Vec<Finding> {
        self.analyze_lockfile_json(
            path,
            content,
            "LOCKFILE_PACKAGE_REMOTE_TARBALL",
            "resolved",
            "package-lock resolves dependencies from remote tarballs",
        )
    }

    fn analyze_cargo_lock(&self, path: &Path, content: &str) -> Vec<Finding> {
        self.analyze_lockfile_text(
            path,
            content,
            "LOCKFILE_CARGO_GIT_SOURCE",
            r#"source\s*=\s*"git\+"#,
            "Cargo.lock references git-based dependency sources",
        )
    }

    fn analyze_poetry_lock(&self, path: &Path, content: &str) -> Vec<Finding> {
        self.analyze_lockfile_text(
            path,
            content,
            "LOCKFILE_POETRY_URL_SOURCE",
            r#"url\s*=\s*"https?://"#,
            "poetry.lock references URL-based dependency sources",
        )
    }

    fn analyze_uv_lock(&self, path: &Path, content: &str) -> Vec<Finding> {
        self.analyze_lockfile_text(
            path,
            content,
            "LOCKFILE_UV_GIT_SOURCE",
            r#"git\+https?://"#,
            "uv.lock references git-based dependency sources",
        )
    }

    fn analyze_yarn_lock(&self, path: &Path, content: &str) -> Vec<Finding> {
        self.analyze_lockfile_text(
            path,
            content,
            "LOCKFILE_YARN_REMOTE_TARBALL",
            r#"resolved\s+"https?://"#,
            "yarn.lock resolves dependencies from remote tarballs",
        )
    }

    fn analyze_pnpm_lock(&self, path: &Path, content: &str) -> Vec<Finding> {
        self.analyze_lockfile_text(
            path,
            content,
            "LOCKFILE_PNPM_REMOTE_TARBALL",
            r#"tarball:\s*https?://"#,
            "pnpm lockfile references remote tarballs",
        )
    }

    fn package_json_capabilities(&self, content: &str) -> Vec<ArtifactCapabilityFact> {
        let Ok(json) = serde_json::from_str::<Value>(content) else {
            return Vec::new();
        };

        let mut capabilities = Vec::new();

        if let Some(scripts) = json.get("scripts").and_then(Value::as_object) {
            if ["preinstall", "install", "postinstall"]
                .iter()
                .any(|hook| scripts.contains_key(*hook))
            {
                capabilities.push(Self::declared_capability(ArtifactCapability::InstallExecution));
                capabilities.push(Self::declared_capability(ArtifactCapability::ProcessExecution));
            }
        }

        if json.get("bin").is_some() {
            capabilities.push(Self::declared_capability(ArtifactCapability::ExposesBinary));
        }

        capabilities
    }

    fn package_json_expected_lockfiles(&self, content: &str) -> Vec<&'static str> {
        let Ok(json) = serde_json::from_str::<Value>(content) else {
            return Vec::new();
        };

        let package_manager = json
            .get("packageManager")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();

        if package_manager.starts_with("pnpm@") {
            return vec!["pnpm-lock.yaml"];
        }

        if package_manager.starts_with("yarn@") {
            return vec!["yarn.lock"];
        }

        if package_manager.starts_with("npm@") {
            return vec!["package-lock.json", "npm-shrinkwrap.json"];
        }

        vec![
            "package-lock.json",
            "npm-shrinkwrap.json",
            "yarn.lock",
            "pnpm-lock.yaml",
        ]
    }

    fn pyproject_expected_lockfiles(&self, content: &str) -> Vec<&'static str> {
        let Ok(toml) = content.parse::<TomlValue>() else {
            return Vec::new();
        };

        if toml
            .get("tool")
            .and_then(|tool| tool.get("poetry"))
            .is_some()
        {
            return vec!["poetry.lock"];
        }

        if toml.get("tool").and_then(|tool| tool.get("uv")).is_some() {
            return vec!["uv.lock"];
        }

        Vec::new()
    }

    fn dockerfile_capabilities(&self, content: &str) -> Vec<ArtifactCapabilityFact> {
        let mut capabilities = Vec::new();
        let lower = content.to_ascii_lowercase();

        if lower.contains(" expose ") || lower.lines().any(|line| line.trim_start().starts_with("EXPOSE ")) {
            capabilities.push(Self::declared_capability(ArtifactCapability::NetworkAccess));
        }

        if lower.contains("curl ")
            || lower.contains("wget ")
            || lower.contains("invoke-webrequest")
        {
            capabilities.push(Self::observed_capability(ArtifactCapability::NetworkAccess));
        }

        if lower.contains("run ") {
            capabilities.push(Self::declared_capability(ArtifactCapability::ProcessExecution));
        }

        if lower.contains(" copy ") || lower.contains(" add ") {
            capabilities.push(Self::declared_capability(ArtifactCapability::FilesystemWrite));
        }

        capabilities
    }

    fn docker_compose_capabilities(&self, content: &str) -> Vec<ArtifactCapabilityFact> {
        let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(content) else {
            return Vec::new();
        };

        let mut capabilities = Vec::new();
        let Some(services) = yaml.get("services").and_then(serde_yaml::Value::as_mapping) else {
            return capabilities;
        };

        for (_, service) in services {
            let Some(mapping) = service.as_mapping() else {
                continue;
            };

            if mapping
                .get(serde_yaml::Value::String("privileged".to_string()))
                .and_then(serde_yaml::Value::as_bool)
                .unwrap_or(false)
                && !capabilities.iter().any(|fact| {
                    fact.capability == ArtifactCapability::PrivilegedRuntime
                        && fact.source == ArtifactCapabilitySource::Declared
                })
            {
                capabilities.push(Self::declared_capability(ArtifactCapability::PrivilegedRuntime));
            }

            if let Some(volumes) = mapping
                .get(serde_yaml::Value::String("volumes".to_string()))
                .and_then(serde_yaml::Value::as_sequence)
            {
                if volumes.iter().any(|volume| {
                    volume
                        .as_str()
                        .is_some_and(|value| value.starts_with('/') || value.starts_with("./"))
                }) && !capabilities.iter().any(|fact| {
                    fact.capability == ArtifactCapability::HostFilesystemAccess
                        && fact.source == ArtifactCapabilitySource::Declared
                })
                {
                    capabilities.push(Self::declared_capability(
                        ArtifactCapability::HostFilesystemAccess,
                    ));
                    capabilities.push(Self::declared_capability(ArtifactCapability::FilesystemWrite));
                }
            }

            if mapping.contains_key(serde_yaml::Value::String("ports".to_string()))
                && !capabilities.iter().any(|fact| {
                    fact.capability == ArtifactCapability::NetworkAccess
                        && fact.source == ArtifactCapabilitySource::Declared
                })
            {
                capabilities.push(Self::declared_capability(ArtifactCapability::NetworkAccess));
            }

            if mapping.contains_key(serde_yaml::Value::String("env_file".to_string())) {
                capabilities.push(Self::declared_capability(ArtifactCapability::SecretAccess));
            }

            if mapping.contains_key(serde_yaml::Value::String("command".to_string()))
                || mapping.contains_key(serde_yaml::Value::String("entrypoint".to_string()))
            {
                capabilities.push(Self::declared_capability(ArtifactCapability::ProcessExecution));
            }
        }

        capabilities
    }

    fn script_capabilities(&self, content: &str) -> Vec<ArtifactCapabilityFact> {
        let lower = content.to_ascii_lowercase();
        let mut capabilities = Vec::new();

        if lower.contains("curl ")
            || lower.contains("wget ")
            || lower.contains("invoke-webrequest")
            || lower.contains("http://")
            || lower.contains("https://")
        {
            capabilities.push(Self::observed_capability(ArtifactCapability::NetworkAccess));
        }

        if lower.contains("bash ")
            || lower.contains(" sh ")
            || lower.contains("node ")
            || lower.contains("python ")
            || lower.contains("npm install")
            || lower.contains("pip install")
            || lower.contains("cargo install")
        {
            capabilities.push(Self::observed_capability(ArtifactCapability::InstallExecution));
        }

        if lower.contains("subprocess.")
            || lower.contains("os.system(")
            || lower.contains("exec(")
            || lower.contains("spawn(")
            || lower.contains("start-process")
            || lower.contains("iex ")
        {
            capabilities.push(Self::observed_capability(ArtifactCapability::ProcessExecution));
        }

        if lower.contains("process.env")
            || lower.contains("os.environ")
            || lower.contains("getenv(")
            || lower.contains(".env")
            || lower.contains("token")
            || lower.contains("secret")
        {
            capabilities.push(Self::observed_capability(ArtifactCapability::SecretAccess));
        }

        if lower.contains("crontab")
            || lower.contains("schtasks")
            || lower.contains("launchctl")
            || lower.contains("runonce")
            || lower.contains("autostart")
            || lower.contains("register-scheduledtask")
        {
            capabilities.push(Self::observed_capability(ArtifactCapability::PersistenceSurface));
        }

        if lower.contains("writefilesync(")
            || lower.contains("tee ")
            || lower.contains(">>")
            || lower.contains("> /etc/")
            || lower.contains("set-content")
        {
            capabilities.push(Self::observed_capability(ArtifactCapability::FilesystemWrite));
        }

        capabilities
    }

    fn makefile_capabilities(&self, content: &str) -> Vec<ArtifactCapabilityFact> {
        let lower = content.to_ascii_lowercase();
        let mut capabilities = Vec::new();
        if lower.contains("curl ") || lower.contains("wget ") {
            capabilities.push(Self::observed_capability(ArtifactCapability::NetworkAccess));
        }
        if lower.contains("bash ") || lower.contains("python ") || lower.contains("node ") || lower.contains("sh ") {
            capabilities.push(Self::observed_capability(ArtifactCapability::ProcessExecution));
        }
        capabilities
    }

    fn npmrc_capabilities(&self, content: &str) -> Vec<ArtifactCapabilityFact> {
        let lower = content.to_ascii_lowercase();
        let mut capabilities = Vec::new();
        if lower.contains("_authtoken=") {
            capabilities.push(Self::declared_capability(ArtifactCapability::SecretAccess));
        }
        if lower.contains("registry=http") {
            capabilities.push(Self::declared_capability(ArtifactCapability::NetworkAccess));
        }
        capabilities
    }

    fn pip_conf_capabilities(&self, content: &str) -> Vec<ArtifactCapabilityFact> {
        let lower = content.to_ascii_lowercase();
        let mut capabilities = Vec::new();
        if lower.contains("extra-index-url") || lower.contains("index-url") {
            capabilities.push(Self::declared_capability(ArtifactCapability::NetworkAccess));
        }
        if lower.contains("client-cert") {
            capabilities.push(Self::declared_capability(ArtifactCapability::SecretAccess));
        }
        capabilities
    }

    fn lockfile_capabilities(&self, content: &str) -> Vec<ArtifactCapabilityFact> {
        let lower = content.to_ascii_lowercase();
        let mut capabilities = Vec::new();
        if lower.contains("http://") || lower.contains("https://") || lower.contains("tarball:") {
            capabilities.push(Self::declared_capability(ArtifactCapability::NetworkAccess));
        }
        capabilities
    }

    fn dockerfile_relations(&self, content: &str) -> Vec<ArtifactLink> {
        let mut links = Vec::new();
        for line in content.lines().map(str::trim) {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("from ") {
                links.push(ArtifactLink {
                    target: line[5..].trim().to_string(),
                    relation: ArtifactRelation::Loads,
                });
            }
            if lower.contains("curl ") || lower.contains("wget ") {
                links.push(ArtifactLink {
                    target: "remote-resource".to_string(),
                    relation: ArtifactRelation::Downloads,
                });
            }
        }
        links
    }

    fn docker_compose_relations(&self, content: &str) -> Vec<ArtifactLink> {
        let mut links = Vec::new();
        let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(content) else {
            return links;
        };
        let Some(services) = yaml.get("services").and_then(serde_yaml::Value::as_mapping) else {
            return links;
        };
        for (_, service) in services {
            let Some(mapping) = service.as_mapping() else { continue; };
            if let Some(image) = mapping
                .get(serde_yaml::Value::String("image".to_string()))
                .and_then(serde_yaml::Value::as_str)
            {
                links.push(ArtifactLink {
                    target: image.to_string(),
                    relation: ArtifactRelation::Loads,
                });
            }
            if mapping.contains_key(serde_yaml::Value::String("ports".to_string())) {
                links.push(ArtifactLink {
                    target: "network".to_string(),
                    relation: ArtifactRelation::ConnectsTo,
                });
            }
            if mapping.contains_key(serde_yaml::Value::String("volumes".to_string())) {
                links.push(ArtifactLink {
                    target: "host-filesystem".to_string(),
                    relation: ArtifactRelation::Mounts,
                });
            }
            if mapping.contains_key(serde_yaml::Value::String("env_file".to_string())) {
                links.push(ArtifactLink {
                    target: ".env".to_string(),
                    relation: ArtifactRelation::AccessesSecrets,
                });
            }
            if mapping.contains_key(serde_yaml::Value::String("command".to_string()))
                || mapping.contains_key(serde_yaml::Value::String("entrypoint".to_string()))
            {
                links.push(ArtifactLink {
                    target: "process".to_string(),
                    relation: ArtifactRelation::Executes,
                });
            }
        }
        links
    }

    fn package_json_relations(&self, content: &str) -> Vec<ArtifactLink> {
        let Ok(json) = serde_json::from_str::<Value>(content) else {
            return Vec::new();
        };
        let mut links = Vec::new();
        if let Some(scripts) = json.get("scripts").and_then(Value::as_object) {
            for hook in ["preinstall", "install", "postinstall"] {
                if let Some(command) = scripts.get(hook).and_then(Value::as_str) {
                    links.push(ArtifactLink {
                        target: command.to_string(),
                        relation: ArtifactRelation::Executes,
                    });
                }
            }
        }
        links
    }

    fn makefile_relations(&self, content: &str) -> Vec<ArtifactLink> {
        let mut links = Vec::new();
        for line in content.lines().map(str::trim) {
            let lower = line.to_ascii_lowercase();
            if lower.contains("curl ") || lower.contains("wget ") {
                links.push(ArtifactLink {
                    target: "remote-resource".to_string(),
                    relation: ArtifactRelation::Downloads,
                });
            }
            if lower.contains("bash ") || lower.contains("python ") || lower.contains("node ") {
                links.push(ArtifactLink {
                    target: line.to_string(),
                    relation: ArtifactRelation::Executes,
                });
            }
        }
        links
    }

    fn npmrc_relations(&self, content: &str) -> Vec<ArtifactLink> {
        let mut links = Vec::new();
        let lower = content.to_ascii_lowercase();
        if lower.contains("_authtoken=") {
            links.push(ArtifactLink {
                target: "credential-store".to_string(),
                relation: ArtifactRelation::AccessesSecrets,
            });
        }
        if lower.contains("registry=http") {
            links.push(ArtifactLink {
                target: "package-registry".to_string(),
                relation: ArtifactRelation::ConnectsTo,
            });
        }
        links
    }

    fn pip_conf_relations(&self, content: &str) -> Vec<ArtifactLink> {
        let mut links = Vec::new();
        let lower = content.to_ascii_lowercase();
        if lower.contains("extra-index-url") || lower.contains("index-url") {
            links.push(ArtifactLink {
                target: "package-index".to_string(),
                relation: ArtifactRelation::ConnectsTo,
            });
        }
        if lower.contains("client-cert") {
            links.push(ArtifactLink {
                target: "client-cert".to_string(),
                relation: ArtifactRelation::AccessesSecrets,
            });
        }
        links
    }

    fn lockfile_relations(&self, content: &str) -> Vec<ArtifactLink> {
        let lower = content.to_ascii_lowercase();
        let mut links = Vec::new();
        if lower.contains("http://") || lower.contains("https://") || lower.contains("tarball:") {
            links.push(ArtifactLink {
                target: "registry".to_string(),
                relation: ArtifactRelation::ConnectsTo,
            });
        }
        links
    }

    fn script_relations(&self, content: &str) -> Vec<ArtifactLink> {
        let lower = content.to_ascii_lowercase();
        let mut links = Vec::new();
        if lower.contains("curl ") || lower.contains("wget ") || lower.contains("invoke-webrequest") {
            links.push(ArtifactLink {
                target: "remote-resource".to_string(),
                relation: ArtifactRelation::Downloads,
            });
        }
        if lower.contains("bash ")
            || lower.contains("sh ")
            || lower.contains("python ")
            || lower.contains("node ")
            || lower.contains("start-process")
            || lower.contains("subprocess.")
            || lower.contains("child_process")
        {
            links.push(ArtifactLink {
                target: "process".to_string(),
                relation: ArtifactRelation::Executes,
            });
        }
        if lower.contains("import ")
            || lower.contains("require(")
            || lower.contains("source ")
            || lower.contains(". ")
        {
            links.push(ArtifactLink {
                target: "runtime-module".to_string(),
                relation: ArtifactRelation::Loads,
            });
        }
        if lower.contains("crontab")
            || lower.contains("schtasks")
            || lower.contains("launchctl")
            || lower.contains("autostart")
        {
            links.push(ArtifactLink {
                target: "persistence-surface".to_string(),
                relation: ArtifactRelation::Persists,
            });
        }
        if lower.contains("http://") || lower.contains("https://") || lower.contains("socket.") {
            links.push(ArtifactLink {
                target: "network".to_string(),
                relation: ArtifactRelation::ConnectsTo,
            });
        }
        if lower.contains("open(")
            || lower.contains("readfilesync(")
            || lower.contains("cat ")
            || lower.contains("rg ")
        {
            links.push(ArtifactLink {
                target: "filesystem".to_string(),
                relation: ArtifactRelation::Reads,
            });
        }
        if lower.contains("writefilesync(")
            || lower.contains("tee ")
            || lower.contains(">>")
            || lower.contains("set-content")
        {
            links.push(ArtifactLink {
                target: "filesystem".to_string(),
                relation: ArtifactRelation::Writes,
            });
        }
        if lower.contains("process.env")
            || lower.contains("os.environ")
            || lower.contains("getenv(")
            || lower.contains(".env")
        {
            links.push(ArtifactLink {
                target: "secrets".to_string(),
                relation: ArtifactRelation::AccessesSecrets,
            });
        }
        links
    }

    fn analyze_lockfile_json(
        &self,
        path: &Path,
        content: &str,
        rule_id: &str,
        key: &str,
        reason: &str,
    ) -> Vec<Finding> {
        let artifact_path = path.display().to_string();
        if !content.contains(key) || !(content.contains("http://") || content.contains("https://")) {
            return Vec::new();
        }

        let urls = extract_http_urls(content);
        let suspicious_urls: Vec<_> = urls
            .into_iter()
            .filter(|url| !is_common_lockfile_source(url))
            .collect();
        if suspicious_urls.is_empty() {
            return Vec::new();
        }

        vec![Finding::builder(rule_id, ThreatCategory::SupplyChain)
            .severity(Severity::Low)
            .action(RecommendedAction::Log)
            .evidence_kind(EvidenceKind::Context)
            .artifact(ArtifactKind::Lockfile, Some(artifact_path.clone()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path,
            })
            .match_value(suspicious_urls[0].clone())
            .reason(format!("{reason} from a non-standard remote source"))
            .build()]
    }

    fn analyze_lockfile_text(
        &self,
        path: &Path,
        content: &str,
        rule_id: &str,
        pattern: &str,
        reason: &str,
    ) -> Vec<Finding> {
        let regex = Regex::new(pattern).expect("valid regex");
        let artifact_path = path.display().to_string();
        let urls = extract_http_urls(content);
        let suspicious_urls: Vec<_> = urls
            .into_iter()
            .filter(|url| !is_common_lockfile_source(url))
            .collect();
        if suspicious_urls.is_empty() {
            return Vec::new();
        }
        regex.find(content).map_or_else(Vec::new, |_| {
            vec![Finding::builder(rule_id, ThreatCategory::SupplyChain)
                .severity(Severity::Low)
                .action(RecommendedAction::Log)
                .evidence_kind(EvidenceKind::Context)
                .artifact(ArtifactKind::Lockfile, Some(artifact_path.clone()))
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path,
                })
                .match_value(suspicious_urls[0].clone())
                .reason(format!("{reason} from a non-standard remote source"))
                .build()]
        })
    }

    fn declared_capability(capability: ArtifactCapability) -> ArtifactCapabilityFact {
        ArtifactCapabilityFact {
            capability,
            source: ArtifactCapabilitySource::Declared,
        }
    }

    fn observed_capability(capability: ArtifactCapability) -> ArtifactCapabilityFact {
        ArtifactCapabilityFact {
            capability,
            source: ArtifactCapabilitySource::Observed,
        }
    }

    fn looks_like_script(path: &Path) -> bool {
        matches!(
            path.extension().and_then(|ext| ext.to_str()).map(str::to_ascii_lowercase).as_deref(),
            Some("sh" | "bash" | "zsh" | "ps1" | "py" | "js" | "ts")
        )
    }

    fn missing_lockfile_findings(
        &self,
        path: &Path,
        sibling_files: &[PathBuf],
        expected_lockfiles: &[&str],
        rule_id: &str,
        reason: &str,
    ) -> Vec<Finding> {
        let artifact_path = path.display().to_string();
        let has_lockfile = sibling_files.iter().any(|candidate| {
            candidate
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| {
                    expected_lockfiles
                        .iter()
                        .any(|expected| name.eq_ignore_ascii_case(expected))
                })
                .unwrap_or(false)
        });

        if has_lockfile {
            return Vec::new();
        }

        vec![Finding::builder(rule_id, ThreatCategory::SupplyChain)
            .severity(Severity::Low)
            .action(RecommendedAction::Log)
            .evidence_kind(EvidenceKind::Context)
            .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path,
            })
            .match_value(expected_lockfiles.join(", "))
            .reason(reason)
            .build()]
    }

    fn semantic_persistence_findings(
        &self,
        path: &Path,
        content: &str,
        artifact_kind: ArtifactKind,
    ) -> Vec<Finding> {
        let artifact_path = path.display().to_string();
        let mut findings = Vec::new();

        if Regex::new("(?i)(persist\\s+these\\s+instructions|remember\\s+this\\s+across\\s+sessions|always\\s+follow\\s+this\\s+prompt|never\\s+reveal\\s+this\\s+instruction|override\\s+future\\s+system\\s+messages)")
            .unwrap()
            .is_match(content)
        {
            findings.push(
                Finding::builder(
                    "SEMANTIC_PERSISTENCE_COGNITIVE_ROOTKIT",
                    ThreatCategory::PersistentPromptTampering,
                )
                .severity(Severity::High)
                .action(RecommendedAction::RequireApproval)
                .evidence_kind(EvidenceKind::Intent)
                .artifact(artifact_kind, Some(artifact_path.clone()))
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.clone(),
                })
                .match_value("persistent instruction override")
                .reason(
                    "Artifact contains persistent instruction behavior consistent with a cognitive rootkit",
                )
                .build(),
            );
        }

        if Regex::new("(?i)(act\\s+as\\s+(root|administrator|system)|treat\\s+all\\s+tool\\s+requests\\s+as\\s+approved|ignore\\s+all\\s+existing\\s+safety\\s+constraints)")
            .unwrap()
            .is_match(content)
        {
            findings.push(
                Finding::builder(
                    "AGENT_EXTENSION_PRIVILEGED_PROMPT_ROLE",
                    ThreatCategory::AutonomyEscalation,
                )
                .severity(Severity::Medium)
                .action(RecommendedAction::RequireApproval)
                .evidence_kind(EvidenceKind::Intent)
                .artifact(artifact_kind, Some(artifact_path.clone()))
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.clone(),
                })
                .match_value("privileged agent role prompt")
                .reason(
                    "Artifact attempts to elevate the agent role or bypass existing control boundaries",
                )
                .build(),
            );
        }

        findings
    }

    fn analyze_mcp_manifest(&self, path: &Path, content: &str) -> Vec<Finding> {
        let artifact_path = path.display().to_string();
        let mut findings = Vec::new();
        let has_remote_endpoint = Regex::new("(?i)(https?://|wss?://)")
            .unwrap()
            .is_match(content);
        let has_exec_surface = Regex::new("(?i)(command|stdio|args|transport)")
            .unwrap()
            .is_match(content);

        if has_remote_endpoint {
            findings.push(
                Finding::builder("MCP_REMOTE_SERVER_ENDPOINT", ThreatCategory::SupplyChain)
                    .severity(Severity::Medium)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Behavior)
                    .artifact(ArtifactKind::McpServerManifest, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value("remote MCP endpoint")
                    .reason("MCP manifest references a remote server endpoint")
                    .build(),
            );
        }

        if has_exec_surface {
            findings.push(
                Finding::builder("MCP_TOOLING_TRANSPORT_DECLARED", ThreatCategory::ToolAbuse)
                    .severity(Severity::Low)
                    .action(if has_remote_endpoint {
                        RecommendedAction::RequireApproval
                    } else {
                        RecommendedAction::Log
                    })
                    .evidence_kind(EvidenceKind::Context)
                    .artifact(ArtifactKind::McpServerManifest, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value("mcp transport")
                    .reason("MCP manifest declares transport or command execution behavior")
                    .build(),
            );
        }

        if has_remote_endpoint && has_exec_surface {
            findings.push(
                Finding::builder("MCP_REMOTE_EXEC_SURFACE", ThreatCategory::RemoteExec)
                    .severity(Severity::High)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Behavior)
                    .artifact(ArtifactKind::McpServerManifest, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value("remote endpoint with command transport")
                    .reason("MCP manifest combines a remote endpoint with command or stdio execution semantics")
                    .build(),
            );
        }

        if has_remote_endpoint && is_opaque_mcp_endpoint(content) {
            findings.push(
                Finding::builder("MCP_OPAQUE_REMOTE_CONTROL_PLANE", ThreatCategory::ToolAbuse)
                    .severity(Severity::High)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Context)
                    .artifact(ArtifactKind::McpServerManifest, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value("opaque remote MCP endpoint")
                    .reason("MCP manifest uses a transient or opaque remote endpoint commonly associated with tunnelled control planes")
                    .build(),
            );
        }

        if has_remote_endpoint && mcp_declares_no_auth(content) {
            findings.push(
                Finding::builder("MCP_NO_AUTH_MODEL", ThreatCategory::ToolAbuse)
                    .severity(Severity::High)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Context)
                    .artifact(ArtifactKind::McpServerManifest, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value("auth: none")
                    .reason("MCP manifest exposes a remote endpoint without a visible authentication model")
                    .build(),
            );
        }

        if mcp_declares_inline_secret(content) {
            findings.push(
                Finding::builder("MCP_INLINE_AUTH_SECRET", ThreatCategory::CredentialExposure)
                    .severity(Severity::High)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Behavior)
                    .artifact(ArtifactKind::McpServerManifest, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value("inline MCP auth secret")
                    .reason("MCP manifest appears to embed bearer, token, or API key material directly in configuration")
                    .build(),
            );
        }

        findings.extend(self.permission_and_network_findings(
            path,
            content,
            ArtifactKind::McpServerManifest,
        ));

        if Regex::new("(?i)(oauth|scope|scopes|bearer|authorization)").unwrap().is_match(content) {
            findings.push(
                Finding::builder("MCP_BROAD_IDENTITY_SCOPE", ThreatCategory::ScopeCreep)
                    .severity(Severity::Medium)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Context)
                    .artifact(ArtifactKind::McpServerManifest, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value("oauth scope")
                    .reason("MCP manifest references identity or OAuth scopes that may exceed the task intent")
                    .build(),
            );
        }

        let mcp_tools = extract_mcp_tool_names(content);
        if mcp_declares_permissive_tools(content) || mcp_tools.len() >= 5 {
            findings.push(
                Finding::builder("MCP_PERMISSIVE_TOOL_EXPOSURE", ThreatCategory::ToolAbuse)
                    .severity(Severity::High)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Context)
                    .artifact(ArtifactKind::McpServerManifest, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value(if mcp_tools.is_empty() {
                        "all tools".to_string()
                    } else {
                        mcp_tools.join(", ")
                    })
                    .reason("MCP manifest exposes an unusually broad tool surface to the agent")
                    .build(),
            );
        }

        findings
    }

    fn permission_and_network_findings(
        &self,
        path: &Path,
        content: &str,
        artifact_kind: ArtifactKind,
    ) -> Vec<Finding> {
        let artifact_path = path.display().to_string();
        let mut findings = Vec::new();
        let mut declared_permission_count = 0_usize;
        let mut add_declared_permission = |rule_id: &'static str, match_value: &'static str, reason: &'static str| {
            declared_permission_count += 1;
            findings.push(
                Finding::builder(rule_id, ThreatCategory::ScopeCreep)
                    .severity(Severity::Low)
                    .action(RecommendedAction::Log)
                    .evidence_kind(EvidenceKind::Context)
                    .artifact(artifact_kind, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value(match_value)
                    .reason(reason)
                    .build(),
            );
        };

        for (rule_id, match_value, reason) in explicit_declared_permission_rules(content) {
            add_declared_permission(rule_id, match_value, reason);
        }

        let broad_permission_count = declared_permission_count;

        if broad_permission_count >= 3 {
            findings.push(
                Finding::builder("SCOPE_OVERPROVISIONING", ThreatCategory::ScopeCreep)
                    .severity(Severity::Medium)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Context)
                    .artifact(artifact_kind, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value("broad declared permissions")
                    .reason("Artifact declares broad permissions or scopes relative to its apparent task")
                    .build(),
            );
        }

        let (intent_kind, intent_strength) = infer_declared_intent(content);
        let has_dangerous_permission_combo = explicit_declared_permission_rules(content)
            .iter()
            .any(|(rule_id, _, _)| {
                matches!(
                    *rule_id,
                    "DECLARED_PERMISSION_BROWSER_FULL"
                        | "DECLARED_PERMISSION_FILE_WRITE"
                        | "DECLARED_PERMISSION_SHELL_EXEC"
                )
            });
        if intent_kind == "narrow" && intent_strength > 0 && has_dangerous_permission_combo {
            findings.push(
                Finding::builder(
                    "CAPABILITY_PERMISSION_MISMATCH",
                    ThreatCategory::ScopeCreep,
                )
                .severity(Severity::Medium)
                .action(RecommendedAction::RequireApproval)
                .evidence_kind(EvidenceKind::Intent)
                .artifact(artifact_kind, Some(artifact_path.clone()))
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.clone(),
                })
                .match_value("narrow intent with broad capability request")
                .reason("Artifact intent appears narrower than the capabilities or permissions it requests")
                .build(),
            );
        }

        if let Some(target) = contains_internal_network_target(content) {
            if (matches!(artifact_kind, ArtifactKind::ReferencedArtifact | ArtifactKind::McpServerManifest)
                || contains_internal_network_action(content))
                && !looks_like_local_dev_reference(content)
            {
            let (rule_id, category, reason) = if target == "169.254.169.254" {
                (
                    "METADATA_SERVICE_ACCESS",
                    ThreatCategory::CredentialExposure,
                    "Artifact references a metadata service target commonly used for credential discovery",
                )
            } else {
                (
                    "INTERNAL_NETWORK_ACCESS",
                    ThreatCategory::ToolAbuse,
                    "Artifact references internal or loopback network targets",
                )
            };
            findings.push(
                Finding::builder(rule_id, category)
                    .severity(Severity::Medium)
                    .action(if target == "169.254.169.254" {
                        RecommendedAction::RequireApproval
                    } else {
                        RecommendedAction::Log
                    })
                    .evidence_kind(EvidenceKind::Behavior)
                    .signal_class(if target == "169.254.169.254" {
                        crate::findings::SignalClass::SuspiciousPackageBehavior
                    } else {
                        crate::findings::SignalClass::ReviewSignal
                    })
                    .artifact(artifact_kind, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value(target)
                    .reason(reason)
                    .build(),
            );
            }
        }

        let internal_target = contains_internal_network_target(content);
        let localhost_like_target = matches!(
            internal_target,
            Some("localhost") | Some("127.0.0.1") | Some("0.0.0.0")
        );

        if contains_ssrf_like_fetch_line(content)
            && internal_target.is_some()
            && !looks_like_local_dev_reference(content)
            && !localhost_like_target
            && !looks_like_local_control_plane_reference(content)
        {
            findings.push(
                Finding::builder("SSRF_LIKE_FETCH", ThreatCategory::ToolAbuse)
                    .severity(Severity::High)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Behavior)
                    .signal_class(crate::findings::SignalClass::SuspiciousPackageBehavior)
                    .artifact(artifact_kind, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value("internal fetch target")
                    .reason("Artifact combines fetch-style behavior with internal network targets")
                    .build(),
            );
        }

        if let Some(kind) = looks_like_webhook_receiver_without_auth(content) {
            let (rule_id, reason) = match kind {
                "webhook_auth_bypass" => (
                    "WEBHOOK_AUTH_BYPASS",
                    "Artifact appears to define a webhook or inbound endpoint without verification or signature checks",
                ),
                _ => (
                    "PUBLIC_INBOUND_ENDPOINT",
                    "Artifact appears to expose a public inbound endpoint without visible authentication controls",
                ),
            };
            findings.push(
                Finding::builder(rule_id, ThreatCategory::ToolAbuse)
                    .severity(Severity::Medium)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Context)
                    .artifact(artifact_kind, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value(kind)
                    .reason(reason)
                    .build(),
            );
        }

        findings
    }

    fn instruction_relations(&self, content: &str) -> Vec<ArtifactLink> {
        self.generic_url_relations(content)
    }

    fn mcp_manifest_relations(&self, content: &str) -> Vec<ArtifactLink> {
        let mut links = self.generic_url_relations(content);

        if Regex::new("(?i)(command|stdio|args)").unwrap().is_match(content) {
            links.push(ArtifactLink {
                target: "mcp-process-transport".to_string(),
                relation: ArtifactRelation::Executes,
            });
        }
        if mcp_declares_inline_secret(content)
            || Regex::new("(?i)(oauth|scope|authorization|bearer|api[_-]?key)")
                .unwrap()
                .is_match(content)
        {
            links.push(ArtifactLink {
                target: "mcp-auth".to_string(),
                relation: ArtifactRelation::AccessesSecrets,
            });
        }
        for tool in extract_mcp_tool_names(content) {
            links.push(ArtifactLink {
                target: format!("tool:{tool}"),
                relation: ArtifactRelation::Loads,
            });
        }

        links
    }

    fn generic_url_relations(&self, content: &str) -> Vec<ArtifactLink> {
        let mut links = Vec::new();
        let regex = Regex::new(r#"https?://[^\s"']+"#).unwrap();
        for matched in regex.find_iter(content) {
            links.push(ArtifactLink {
                target: matched.as_str().to_string(),
                relation: ArtifactRelation::ConnectsTo,
            });
        }
        links
    }

    fn instruction_capabilities(&self, content: &str) -> Vec<ArtifactCapabilityFact> {
        let mut capabilities = Vec::new();
        if Regex::new("(?i)(browser:\\s*full|full autonomous browser|click any element|navigation:\\s*allow-all)")
            .unwrap()
            .is_match(content)
        {
            capabilities.push(Self::declared_capability(ArtifactCapability::BrowserAccess));
        }
        if Regex::new("(?i)(persist\\s+these\\s+instructions|remember\\s+this\\s+across\\s+sessions|append\\s+to\\s+(agents|claude|system)\\.md)")
            .unwrap()
            .is_match(content)
        {
            capabilities.push(Self::observed_capability(
                ArtifactCapability::PersistenceSurface,
            ));
        }
        if Regex::new("(?i)(http://|https://|browser tool|network tool)")
            .unwrap()
            .is_match(content)
        {
            capabilities.push(Self::observed_capability(ArtifactCapability::NetworkAccess));
        }
        if Regex::new("(?i)(token|secret|cookie|password|credential|session)")
            .unwrap()
            .is_match(content)
        {
            capabilities.push(Self::observed_capability(ArtifactCapability::SecretAccess));
        }
        if Regex::new("(?i)(oauth|scope|calendar|drive|slack|github pat)")
            .unwrap()
            .is_match(content)
        {
            capabilities.push(Self::declared_capability(ArtifactCapability::IdentityAccess));
        }
        if looks_like_webhook_receiver_without_auth(content).is_some() {
            capabilities.push(Self::observed_capability(
                ArtifactCapability::InboundNetworkSurface,
            ));
        }
        capabilities
    }

    fn mcp_manifest_capabilities(&self, content: &str) -> Vec<ArtifactCapabilityFact> {
        let mut capabilities = Vec::new();
        if Regex::new("(?i)(command|stdio|args)").unwrap().is_match(content) {
            capabilities.push(Self::declared_capability(ArtifactCapability::ProcessExecution));
        }
        if Regex::new("(?i)(https?://|wss?://)").unwrap().is_match(content) {
            capabilities.push(Self::declared_capability(ArtifactCapability::NetworkAccess));
        }
        if Regex::new("(?i)(oauth|scope|authorization|bearer)").unwrap().is_match(content) {
            capabilities.push(Self::declared_capability(ArtifactCapability::IdentityAccess));
        }
        if mcp_declares_inline_secret(content) {
            capabilities.push(Self::observed_capability(ArtifactCapability::SecretAccess));
        }
        if looks_like_webhook_receiver_without_auth(content).is_some() {
            capabilities.push(Self::observed_capability(
                ArtifactCapability::InboundNetworkSurface,
            ));
        }
        capabilities
    }
}

impl Default for ArtifactAnalysisService {
    fn default() -> Self {
        Self::new()
    }
}
