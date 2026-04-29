//! Detectors covering secret / credential / sensitive-system-state access
//! in Python and Node scripts.

use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};

pub(crate) fn detect_python_secret_system_access(
    content_lower: &str,
    language: &str,
    artifact_path: &str,
) -> Vec<Finding> {
    // Pre-fix only `pathlib.path.home()` (the qualified form `pathlib.Path.home()`
    // post-lowercase) was detected. The most common idiom — `from pathlib import Path`
    // followed by `Path.home()` — lowercases to `path.home()` and was missed. We add
    // `.home()` on a `path` token plus the `os.path.expanduser` family. To keep the
    // false-positive rate low for non-Python text we still require either an explicit
    // `pathlib`/`path.home()` form or an `os.` qualifier.
    let mentions_home_idiom = content_lower.contains("pathlib.path.home()")
        || content_lower.contains("path.home()")
        || content_lower.contains("os.path.expanduser(")
        || content_lower.contains("os.path.expandvars(");
    if language != "py"
        || !(content_lower.contains("open(\"/etc/")
            || content_lower.contains("open('/etc/")
            || content_lower.contains("os.getenv(")
            || mentions_home_idiom
            || content_lower.contains("os.environ"))
    {
        return Vec::new();
    }
    vec![Finding::builder(
        "SCRIPT_PYTHON_SECRET_OR_SYSTEM_ACCESS",
        ThreatCategory::CredentialExposure,
    )
    .severity(Severity::Medium)
    .action(RecommendedAction::RequireApproval)
    .evidence_kind(EvidenceKind::Behavior)
    .matched_on(MatchTarget::ReferencedFile {
        path: artifact_path.to_string(),
    })
    .artifact(
        ArtifactKind::ReferencedArtifact,
        Some(artifact_path.to_string()),
    )
    .match_value("python secret/system access")
    .reason("Python script reads environment variables, home paths, or system files")
    .build()]
}

pub(crate) fn detect_node_secret_fs_access(
    content_lower: &str,
    language: &str,
    artifact_path: &str,
) -> Vec<Finding> {
    if !matches!(language, "js" | "ts" | "mjs" | "cjs" | "mts" | "cts")
        || !((content_lower.contains("process.env")
            && (content_lower.contains("token")
                || content_lower.contains("secret")
                || content_lower.contains("cookie")
                || content_lower.contains("session")
                || content_lower.contains("auth")))
            || content_lower.contains("fs.readfilesync(process.env")
            || content_lower.contains("fs.readfilesync(\"/etc/")
            || content_lower.contains("fs.readfilesync('/etc/"))
    {
        return Vec::new();
    }
    // `RequireApproval` (not `Block`) is intentional: this is a single-signal
    // heuristic (substring match on `process.env` + a sensitive keyword). A
    // `Block` action combined with `CredentialExposure` (which maps to
    // `SignalClass::MaliciousBehavior`) would short-circuit verdict logic to
    // `Verdict::Malicious` for any benign script reading e.g.
    // `process.env.AUTH_API_URL`. Mirrors the Python sibling
    // `detect_python_secret_system_access` which uses the same action.
    vec![Finding::builder(
        "SCRIPT_NODE_SECRET_OR_FS_ACCESS",
        ThreatCategory::CredentialExposure,
    )
    .severity(Severity::Medium)
    .action(RecommendedAction::RequireApproval)
    .evidence_kind(EvidenceKind::Behavior)
    .matched_on(MatchTarget::ReferencedFile {
        path: artifact_path.to_string(),
    })
    .artifact(
        ArtifactKind::ReferencedArtifact,
        Some(artifact_path.to_string()),
    )
    .match_value("process.env/fs access")
    .reason("Node script accesses environment variables or sensitive filesystem paths")
    .build()]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: a single-signal Node script reading `process.env.<name>`
    /// must NOT emit a `RecommendedAction::Block` finding. `Block` combined
    /// with `ThreatCategory::CredentialExposure` (which maps to
    /// `SignalClass::MaliciousBehavior`) short-circuits the verdict
    /// pipeline to `Verdict::Malicious` via
    /// `verdict::predicates::has_malicious_behavior`, producing false
    /// positives on benign scripts that read `process.env.AUTH_API_URL`,
    /// `process.env.SESSION_PREFIX`, etc.
    #[test]
    fn detect_node_secret_fs_access_does_not_emit_block_action() {
        let script = "console.log(process.env.AUTH_API_URL);\n\
                      const t = process.env.token;\n";
        let lower = script.to_ascii_lowercase();
        let findings = detect_node_secret_fs_access(&lower, "js", "/tmp/install.js");
        assert_eq!(findings.len(), 1, "expected exactly one finding");
        assert_eq!(
            findings[0].recommended_action,
            RecommendedAction::RequireApproval,
            "single-signal env-var heuristic must not request Block; \
             got {:?}",
            findings[0].recommended_action,
        );
    }

    /// Contract: the Python detector matches the common
    /// `from pathlib import Path; Path.home()` idiom and the
    /// `os.path.expanduser("~")` idiom. Pre-fix only the qualified
    /// `pathlib.Path.home()` form was detected (lowercases to
    /// `pathlib.path.home()` literal substring), missing the bare
    /// `Path.home()` after a `from pathlib import Path` import — the
    /// most common shape in real code.
    #[test]
    fn detect_python_secret_system_access_matches_path_home_idiom() {
        let positives = [
            (
                "from pathlib import Path\np = Path.home() / '.aws/credentials'\n",
                "Path.home() bare idiom",
            ),
            (
                "import os\np = os.path.expanduser(\"~/.ssh/id_rsa\")\n",
                "os.path.expanduser",
            ),
            (
                "import os\np = os.path.expandvars(\"$HOME/.aws\")\n",
                "os.path.expandvars",
            ),
            (
                "import pathlib\np = pathlib.Path.home() / 'secret'\n",
                "pathlib.Path.home() qualified — pre-fix coverage MUST remain",
            ),
        ];
        for (script, label) in positives {
            let lower = script.to_ascii_lowercase();
            let findings = detect_python_secret_system_access(&lower, "py", "/tmp/x.py");
            assert_eq!(
                findings.len(),
                1,
                "{label}: expected exactly one finding for {script:?}, got {findings:?}",
            );
            assert_eq!(
                findings[0].rule_id, "SCRIPT_PYTHON_SECRET_OR_SYSTEM_ACCESS",
                "{label}: wrong rule_id"
            );
        }
    }

    /// Contract: a script that mentions `path.home()` but is NOT Python
    /// (different language tag) MUST NOT fire the detector. Guards
    /// against the broadened substring match leaking into JS/TS/PowerShell.
    #[test]
    fn detect_python_secret_system_access_does_not_fire_for_non_python() {
        let script = "from pathlib import Path\np = Path.home()\n";
        let lower = script.to_ascii_lowercase();
        for non_py in ["js", "ts", "ps1", "sh"] {
            let findings = detect_python_secret_system_access(&lower, non_py, "/tmp/x");
            assert!(
                findings.is_empty(),
                "{non_py}: must NOT fire on non-Python language; got {findings:?}",
            );
        }
    }

    /// Contract: the detector still fires on the documented patterns —
    /// fix 1 only weakens the action, not the recall. The Python sibling
    /// `detect_python_secret_system_access` shipped this same shape.
    #[test]
    fn detect_node_secret_fs_access_still_fires_on_known_patterns() {
        let positives = [
            ("const t = process.env.token;\n", "process.env+token"),
            (
                "const c = process.env.session_cookie;\n",
                "process.env+cookie",
            ),
            (
                "const fs = require('fs');\nfs.readFileSync(\"/etc/shadow\");\n",
                "fs.readFileSync(\"/etc/...)",
            ),
            (
                "const fs = require('fs');\nfs.readFileSync(process.env.HOME);\n",
                "fs.readFileSync(process.env",
            ),
        ];
        for (script, label) in positives {
            let lower = script.to_ascii_lowercase();
            let findings = detect_node_secret_fs_access(&lower, "js", "/tmp/install.js");
            assert_eq!(
                findings.len(),
                1,
                "{label}: expected exactly one finding for {script:?}",
            );
            assert_eq!(
                findings[0].rule_id, "SCRIPT_NODE_SECRET_OR_FS_ACCESS",
                "{label}: wrong rule_id"
            );
            assert_eq!(
                findings[0].recommended_action,
                RecommendedAction::RequireApproval,
                "{label}: action must be RequireApproval"
            );
        }
    }
}
