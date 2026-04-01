use super::shared::*;

#[test]
fn cli_commands_stay_on_public_core_surface() {
    let forbidden = [
        "skill_veil_core::scanner_execution",
        "skill_veil_core::scanner_graph",
        "skill_veil_core::scanner_support",
        "skill_veil_core::policy_state",
    ];
    assert_no_forbidden_tokens(COMMANDS_SRC, "skill-veil-cli/src/commands.rs", &forbidden);
    assert_no_forbidden_tokens(DATASET_SRC, "skill-veil-cli/src/dataset.rs", &forbidden);
}

#[test]
fn cli_roots_delegate_filesystem_io_to_support_modules() {
    let forbidden = ["std::fs", "serde_json::to_string_pretty(", "std::fs::write"];
    assert_no_forbidden_tokens(COMMANDS_SRC, "skill-veil-cli/src/commands.rs", &forbidden);
    assert_no_forbidden_tokens(DATASET_SRC, "skill-veil-cli/src/dataset.rs", &forbidden);
    assert!(
        COMMANDS_IO_SRC.contains("std::fs"),
        "commands/io.rs should own commands filesystem access"
    );
    assert!(
        DATASET_OUTPUT_SRC.contains("std::fs"),
        "dataset/output.rs should own dataset filesystem access"
    );
}

#[test]
fn cli_roots_delegate_use_cases_to_specialized_modules() {
    let forbidden = [
        "baseline_from_reports",
        "diff_reports_with_policy_state",
        "format_diff_text",
        "format_diff_ci_summary",
    ];
    assert_no_forbidden_tokens(COMMANDS_SRC, "skill-veil-cli/src/commands.rs", &forbidden);
    assert!(
        COMMANDS_BASELINE_SRC.contains("baseline_from_reports"),
        "commands/baseline.rs should own baseline workflows"
    );
    assert!(
        COMMANDS_DIFF_SRC.contains("diff_reports_with_policy_state"),
        "commands/diff.rs should own diff workflows"
    );
}
