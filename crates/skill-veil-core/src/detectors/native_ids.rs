//! Stable rule IDs emitted by the native (Rust) detectors: the
//! Unicode-deception pass ([`crate::unicode_deception`]), the MCP manifest
//! detector ([`crate::detectors::mcp`]), the dependency typosquat detector
//! ([`crate::detectors::typosquat`]), the Python `.pyc` bytecode integrity
//! detector ([`crate::detectors::bytecode`]), and the shell-pipeline taint
//! detector ([`crate::detectors::scripts::pipeline`]).
//!
//! # Stability contract
//!
//! These IDs are public API on the same footing as the `official` YAML rule
//! pack. They surface in JSON/SARIF output and operators key baselines and
//! waivers on them, so renaming or removing one breaks downstream pins — a
//! breaking change. The contract is documented under "Native detector IDs"
//! in `CLAUDE.md` / `AGENTS.md`. [`NATIVE_DETECTOR_RULE_IDS`] is the frozen
//! registry; the `native_id_registry_is_frozen` test fails on any drift,
//! forcing the change to be deliberate.

pub const UNICODE_INVISIBLE_CHARS: &str = "UNICODE_INVISIBLE_CHARS";
pub const UNICODE_BIDI_OVERRIDE: &str = "UNICODE_BIDI_OVERRIDE";
pub const UNICODE_TAG_BLOCK: &str = "UNICODE_TAG_BLOCK";
pub const UNICODE_HOMOGLYPH_MIX: &str = "UNICODE_HOMOGLYPH_MIX";

pub const MCP_REMOTE_SERVER_ENDPOINT: &str = "MCP_REMOTE_SERVER_ENDPOINT";
pub const MCP_TOOLING_TRANSPORT_DECLARED: &str = "MCP_TOOLING_TRANSPORT_DECLARED";
pub const MCP_REMOTE_EXEC_SURFACE: &str = "MCP_REMOTE_EXEC_SURFACE";
pub const MCP_OPAQUE_REMOTE_CONTROL_PLANE: &str = "MCP_OPAQUE_REMOTE_CONTROL_PLANE";
pub const MCP_NO_AUTH_MODEL: &str = "MCP_NO_AUTH_MODEL";
pub const MCP_INLINE_AUTH_SECRET: &str = "MCP_INLINE_AUTH_SECRET";
pub const MCP_BROAD_IDENTITY_SCOPE: &str = "MCP_BROAD_IDENTITY_SCOPE";
pub const MCP_PERMISSIVE_TOOL_EXPOSURE: &str = "MCP_PERMISSIVE_TOOL_EXPOSURE";
pub const MCP_WILDCARD_CAPABILITY: &str = "MCP_WILDCARD_CAPABILITY";
pub const MCP_TOOL_DESCRIPTION_HIDDEN_INSTRUCTION: &str = "MCP_TOOL_DESCRIPTION_HIDDEN_INSTRUCTION";
pub const MCP_UNDERDECLARED_CAPABILITY: &str = "MCP_UNDERDECLARED_CAPABILITY";
pub const MCP_ENV_PROCESS_INJECTION: &str = "MCP_ENV_PROCESS_INJECTION";

pub const SUPPLY_CHAIN_TYPOSQUAT: &str = "SUPPLY_CHAIN_TYPOSQUAT";

pub const BYTECODE_PYC_INVALID_MAGIC: &str = "BYTECODE_PYC_INVALID_MAGIC";
pub const BYTECODE_PYC_SOURCELESS: &str = "BYTECODE_PYC_SOURCELESS";
pub const BYTECODE_PYC_SUSPICIOUS_CONTENT: &str = "BYTECODE_PYC_SUSPICIOUS_CONTENT";

pub const PIPELINE_FETCH_TO_SHELL: &str = "PIPELINE_FETCH_TO_SHELL";
pub const PIPELINE_SECRET_TO_NETWORK: &str = "PIPELINE_SECRET_TO_NETWORK";

/// Frozen registry of every rule ID emitted by the native parity detectors.
/// Used by the public stability contract and the regression harness in
/// `tests/native_detector_ids.rs`.
pub const NATIVE_DETECTOR_RULE_IDS: &[&str] = &[
    UNICODE_INVISIBLE_CHARS,
    UNICODE_BIDI_OVERRIDE,
    UNICODE_TAG_BLOCK,
    UNICODE_HOMOGLYPH_MIX,
    MCP_REMOTE_SERVER_ENDPOINT,
    MCP_TOOLING_TRANSPORT_DECLARED,
    MCP_REMOTE_EXEC_SURFACE,
    MCP_OPAQUE_REMOTE_CONTROL_PLANE,
    MCP_NO_AUTH_MODEL,
    MCP_INLINE_AUTH_SECRET,
    MCP_BROAD_IDENTITY_SCOPE,
    MCP_PERMISSIVE_TOOL_EXPOSURE,
    MCP_WILDCARD_CAPABILITY,
    MCP_TOOL_DESCRIPTION_HIDDEN_INSTRUCTION,
    MCP_UNDERDECLARED_CAPABILITY,
    MCP_ENV_PROCESS_INJECTION,
    SUPPLY_CHAIN_TYPOSQUAT,
    BYTECODE_PYC_INVALID_MAGIC,
    BYTECODE_PYC_SOURCELESS,
    BYTECODE_PYC_SUSPICIOUS_CONTENT,
    PIPELINE_FETCH_TO_SHELL,
    PIPELINE_SECRET_TO_NETWORK,
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn native_id_registry_is_frozen() {
        let expected = [
            "BYTECODE_PYC_INVALID_MAGIC",
            "BYTECODE_PYC_SOURCELESS",
            "BYTECODE_PYC_SUSPICIOUS_CONTENT",
            "MCP_BROAD_IDENTITY_SCOPE",
            "MCP_ENV_PROCESS_INJECTION",
            "MCP_INLINE_AUTH_SECRET",
            "MCP_NO_AUTH_MODEL",
            "MCP_OPAQUE_REMOTE_CONTROL_PLANE",
            "MCP_PERMISSIVE_TOOL_EXPOSURE",
            "MCP_REMOTE_EXEC_SURFACE",
            "MCP_REMOTE_SERVER_ENDPOINT",
            "MCP_TOOLING_TRANSPORT_DECLARED",
            "MCP_TOOL_DESCRIPTION_HIDDEN_INSTRUCTION",
            "MCP_UNDERDECLARED_CAPABILITY",
            "MCP_WILDCARD_CAPABILITY",
            "PIPELINE_FETCH_TO_SHELL",
            "PIPELINE_SECRET_TO_NETWORK",
            "SUPPLY_CHAIN_TYPOSQUAT",
            "UNICODE_BIDI_OVERRIDE",
            "UNICODE_HOMOGLYPH_MIX",
            "UNICODE_INVISIBLE_CHARS",
            "UNICODE_TAG_BLOCK",
        ];
        let mut actual: Vec<&str> = NATIVE_DETECTOR_RULE_IDS.to_vec();
        actual.sort_unstable();
        assert_eq!(
            actual, expected,
            "native detector ID registry changed — renaming or removing a \
             public ID is a breaking change; update the contract in CLAUDE.md / \
             AGENTS.md and this frozen list deliberately"
        );
    }

    #[test]
    fn native_ids_are_unique() {
        let unique: BTreeSet<&&str> = NATIVE_DETECTOR_RULE_IDS.iter().collect();
        assert_eq!(unique.len(), NATIVE_DETECTOR_RULE_IDS.len());
    }
}
