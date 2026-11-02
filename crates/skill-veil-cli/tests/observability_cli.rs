use std::process::Command;

use serde_json::Value;

#[test]
fn json_runtime_error_preserves_context_without_leaking_secrets() {
    let missing = tempfile::tempdir()
        .expect("tempdir")
        .path()
        .join("api_key=supersecret.yaml");
    let output = Command::new(env!("CARGO_BIN_EXE_skill-veil"))
        .args([
            "--log-format",
            "json",
            "--log-level",
            "info",
            "--correlation-id",
            "test-correlation",
            "--environment",
            "ci",
            "policy",
            "validate",
        ])
        .arg(missing)
        .output()
        .expect("run skill-veil");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(!stderr.contains("supersecret"));
    let events: Vec<Value> = stderr
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSON log event"))
        .collect();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["event_name"], "command.started");
    let completed = &events[1];
    assert_eq!(completed["level"], "ERROR");
    assert_eq!(completed["event_name"], "command.completed");
    assert_eq!(completed["status"], "error");
    assert_eq!(completed["outcome"], "failed");
    assert_eq!(completed["error_type"], "runtime");
    assert_eq!(completed["error_code"], "SV_RUNTIME_ERROR");
    assert_eq!(completed["span"]["service"], "skill-veil");
    assert_eq!(completed["span"]["component"], "cli");
    assert_eq!(completed["span"]["operation"], "policy");
    assert_eq!(completed["span"]["environment"], "ci");
    assert_eq!(completed["span"]["correlation_id"], "test-correlation");
    assert!(completed["duration_ms"].is_u64());
    assert!(completed["timestamp"]
        .as_str()
        .is_some_and(|timestamp| timestamp.ends_with('Z')));
}

#[test]
fn successful_scan_emits_one_bounded_completion_event() {
    let dir = tempfile::tempdir().expect("tempdir");
    let skill = dir.path().join("SKILL.md");
    std::fs::write(
        &skill,
        "# Safe skill\n\n## Usage\n\nDescribe local files.\n",
    )
    .expect("write skill");
    let output = Command::new(env!("CARGO_BIN_EXE_skill-veil"))
        .args(["--log-format", "json", "--log-level", "info", "scan-file"])
        .arg(&skill)
        .args([
            "--format",
            "json",
            "--no-update-check",
            "--no-llm-enrich",
            "--no-vt-enrich",
            "--no-promptintel-enrich",
        ])
        .output()
        .expect("run skill-veil");

    assert!(output.status.success());
    let reports: Value = serde_json::from_slice(&output.stdout).expect("JSON scan output");
    assert_eq!(reports.as_array().map(Vec::len), Some(1));
    let events: Vec<Value> = String::from_utf8(output.stderr)
        .expect("utf8 stderr")
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSON log event"))
        .collect();
    let scan_events: Vec<_> = events
        .iter()
        .filter(|event| event["event_name"] == "scan.completed")
        .collect();
    assert_eq!(scan_events.len(), 1);
    let completed = scan_events[0];
    assert_eq!(completed["status"], "success");
    assert_eq!(completed["outcome"], "completed");
    assert_eq!(completed["package_count"], 1);
    assert!(completed["finding_count"].is_u64());
    assert_eq!(completed["error_count"], 0);
    assert!(completed["duration_ms"].is_u64());
    assert!(events.len() <= 4, "unexpected INFO log volume: {events:?}");
}

#[test]
fn environment_configuration_writes_json_events_to_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log_path = dir.path().join("events.jsonl");
    let output = Command::new(env!("CARGO_BIN_EXE_skill-veil"))
        .args(["rules", "list", "--format", "json"])
        .env("SKILL_VEIL_LOG_FORMAT", "json")
        .env("SKILL_VEIL_LOG_LEVEL", "info")
        .env("SKILL_VEIL_LOG_FILE", &log_path)
        .env("SKILL_VEIL_CORRELATION_ID", "environment-correlation")
        .env("SKILL_VEIL_ENVIRONMENT", "test")
        .env_remove("RUST_LOG")
        .output()
        .expect("run skill-veil");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let events: Vec<Value> = std::fs::read_to_string(log_path)
        .expect("read log file")
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSON log event"))
        .collect();
    assert_eq!(
        events.first().expect("start event")["event_name"],
        "command.started"
    );
    let completed = events.last().expect("completion event");
    assert_eq!(completed["event_name"], "command.completed");
    assert_eq!(completed["status"], "success");
    assert_eq!(
        completed["span"]["correlation_id"],
        "environment-correlation"
    );
    assert_eq!(completed["span"]["environment"], "test");
}

#[test]
fn default_warn_level_suppresses_success_lifecycle_events() {
    let output = Command::new(env!("CARGO_BIN_EXE_skill-veil"))
        .args(["rules", "list", "--format", "json"])
        .env_remove("RUST_LOG")
        .env_remove("SKILL_VEIL_LOG_LEVEL")
        .env_remove("SKILL_VEIL_LOG_FILE")
        .output()
        .expect("run skill-veil");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
}
