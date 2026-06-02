//! Dynamic-behavior sandbox channel.
//!
//! Executes a skill's scripts and an instrumented agent inside a
//! hardened, gVisor-isolated container and turns the observed runtime
//! behavior into advisory findings. Mirrors the NOVA / YARA post-scan
//! channels: it is strictly opt-in (`--dynamic`), runs after the verdict,
//! and only adds `ReviewSignal` findings -- it never recomputes the
//! deterministic verdict.
//!
//! Layering: [`policy`] (hardening), [`observation`] (parse the
//! observer's JSON), and [`mapping`] (behavior -> finding) are pure and
//! test without a Docker daemon. [`executor`] is the only layer that
//! touches Docker; the channel drives it through the [`SandboxExecutor`]
//! trait so tests inject a fake. The channel degrades gracefully (skips
//! with a note) when Docker or the gVisor runtime is absent.

pub(crate) mod executor;
pub(crate) mod mapping;
pub(crate) mod observation;
pub(crate) mod policy;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use skill_veil_core::Finding;

use executor::{DockerExecutor, SandboxExecutor};
use policy::{SandboxPolicy, SandboxRuntime};

/// In-container command passed to the observer entrypoint: run BOTH the
/// referenced scripts and the instrumented agent (the operator's chosen
/// coverage), and emit the observation JSON on stdout.
const OBSERVER_COMMAND: &[&str] = &["--scripts", "--agent"];

/// Outcome of a sandbox run, ready to inject into the scan results.
#[derive(Debug)]
pub(crate) struct SandboxReport {
    pub(crate) source_path: PathBuf,
    pub(crate) findings: Vec<Finding>,
    pub(crate) runtime: SandboxRuntime,
    pub(crate) timed_out: bool,
    pub(crate) truncated: bool,
}

impl SandboxReport {
    /// Group findings by the analysed artifact path, for injection via the
    /// shared `attach_findings_by_path` helper (same shape NOVA/YARA use).
    pub(crate) fn findings_by_path(&self) -> HashMap<PathBuf, Vec<Finding>> {
        let mut out: HashMap<PathBuf, Vec<Finding>> = HashMap::new();
        if !self.findings.is_empty() {
            out.insert(self.source_path.clone(), self.findings.clone());
        }
        out
    }
}

/// Directory to mount read-only into the sandbox: the artifact itself if
/// it is a directory, otherwise its parent (so a single `SKILL.md` brings
/// its sibling scripts along).
fn mount_dir_for(target: &Path) -> PathBuf {
    match std::fs::metadata(target) {
        Ok(meta) if meta.is_dir() => target.to_path_buf(),
        _ => target
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(".")),
    }
}

/// Run the dynamic sandbox against `target` using the production Docker
/// executor. `require_gvisor` rejects the weaker runc fallback.
pub(crate) fn evaluate_against_target(
    target: &Path,
    require_gvisor: bool,
) -> Result<Option<SandboxReport>> {
    run_with_executor(target, require_gvisor, &DockerExecutor)
}

fn run_with_executor(
    target: &Path,
    require_gvisor: bool,
    executor: &dyn SandboxExecutor,
) -> Result<Option<SandboxReport>> {
    let caps = executor.capabilities();
    if !caps.docker {
        return Ok(None);
    }
    let runtime = if caps.gvisor {
        SandboxRuntime::Gvisor
    } else if require_gvisor {
        return Ok(None);
    } else {
        SandboxRuntime::Runc
    };

    let mut policy = SandboxPolicy::hardened(mount_dir_for(target));
    policy.runtime = runtime;
    if !executor.ensure_image(&policy.image)? {
        return Ok(None);
    }
    let cmd: Vec<String> = OBSERVER_COMMAND.iter().map(|s| (*s).to_string()).collect();
    let args = policy.to_docker_run_args(&cmd);

    let raw = executor.run(&args, Duration::from_secs(policy.timeout_secs))?;
    let observation = match observation::SandboxObservation::parse(&raw.stdout) {
        Ok(obs) => obs,
        Err(err) => {
            tracing::warn!("sandbox observer output was not valid JSON: {err}");
            observation::SandboxObservation::default()
        }
    };
    let findings = mapping::observation_to_findings(&observation, target);
    let timed_out = raw.timed_out || observation.timed_out;
    let truncated = observation.truncated;
    if findings.is_empty() && !timed_out && !truncated {
        return Ok(None);
    }
    Ok(Some(SandboxReport {
        source_path: target.to_path_buf(),
        findings,
        runtime,
        timed_out,
        truncated,
    }))
}

/// Operator-facing summary block (text output only).
pub(crate) fn render_text_block(report: &SandboxReport) -> String {
    let mut out = String::from("\n--- Dynamic sandbox ---\n");
    let runtime = match report.runtime {
        SandboxRuntime::Gvisor => "gVisor (runsc)",
        SandboxRuntime::Runc => "runc (WEAKER: host kernel shared)",
    };
    out.push_str(&format!("  runtime: {runtime}\n"));
    if report.timed_out {
        out.push_str("  note:    run hit the wall-clock timeout (partial observation)\n");
    }
    if report.truncated {
        out.push_str("  note:    observer truncated output (behavior flood)\n");
    }
    if report.findings.is_empty() {
        out.push_str("  result:  no behaviors observed\n");
    } else {
        out.push_str(&format!("  behaviors: {}\n", report.findings.len()));
        for f in &report.findings {
            out.push_str(&format!(
                "    - {} :: {}\n",
                crate::util::terminal_safe::sanitise_for_terminal(&f.rule_id),
                crate::util::terminal_safe::sanitise_for_terminal(&f.match_value),
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use executor::{RawRun, SandboxCapabilities};

    struct FakeExecutor {
        caps: SandboxCapabilities,
        stdout: String,
        timed_out: bool,
    }

    impl SandboxExecutor for FakeExecutor {
        fn capabilities(&self) -> SandboxCapabilities {
            self.caps
        }
        fn ensure_image(&self, _tag: &str) -> Result<bool> {
            Ok(true)
        }
        fn run(&self, _docker_args: &[String], _timeout: Duration) -> Result<RawRun> {
            Ok(RawRun {
                stdout: self.stdout.clone(),
                timed_out: self.timed_out,
            })
        }
    }

    /// # Contract (end-to-end, daemon-free)
    /// Given a gVisor-capable host and an observer that reports behaviors,
    /// the channel produces advisory findings attributed to the target.
    #[test]
    fn produces_findings_from_observer_output() {
        let exec = FakeExecutor {
            caps: SandboxCapabilities { docker: true, gvisor: true },
            stdout: r#"{"behaviors":[{"class":"network_connect","detail":"evil.invalid:443","source":"agent"}]}"#.to_string(),
            timed_out: false,
        };
        let report = run_with_executor(Path::new("pkg/SKILL.md"), true, &exec)
            .unwrap()
            .expect("a behavior must produce a report");
        assert_eq!(report.runtime, SandboxRuntime::Gvisor);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "SANDBOX_NETWORK_CONNECT");
        assert!(report
            .findings_by_path()
            .contains_key(Path::new("pkg/SKILL.md")));
    }

    /// # Contract (negative)
    /// No Docker daemon -> the channel skips silently (returns None), never
    /// fails the scan.
    #[test]
    fn skips_when_docker_absent() {
        let exec = FakeExecutor {
            caps: SandboxCapabilities {
                docker: false,
                gvisor: false,
            },
            stdout: String::new(),
            timed_out: false,
        };
        assert!(run_with_executor(Path::new("x"), true, &exec)
            .unwrap()
            .is_none());
    }

    /// # Contract (negative)
    /// gVisor required but unavailable -> skip rather than silently fall
    /// back to the weaker runc runtime.
    #[test]
    fn skips_when_gvisor_required_but_absent() {
        let exec = FakeExecutor {
            caps: SandboxCapabilities {
                docker: true,
                gvisor: false,
            },
            stdout: r#"{"behaviors":[{"class":"process_spawn","detail":"x"}]}"#.to_string(),
            timed_out: false,
        };
        assert!(run_with_executor(Path::new("x"), true, &exec)
            .unwrap()
            .is_none());
    }

    /// # Contract
    /// When gVisor is not required and absent, the channel falls back to
    /// runc and the report records the weaker runtime so the operator is
    /// warned.
    #[test]
    fn falls_back_to_runc_when_not_required() {
        let exec = FakeExecutor {
            caps: SandboxCapabilities {
                docker: true,
                gvisor: false,
            },
            stdout: r#"{"behaviors":[{"class":"process_spawn","detail":"x"}]}"#.to_string(),
            timed_out: false,
        };
        let report = run_with_executor(Path::new("x"), false, &exec)
            .unwrap()
            .unwrap();
        assert_eq!(report.runtime, SandboxRuntime::Runc);
        assert!(render_text_block(&report).contains("WEAKER"));
    }

    /// # Contract
    /// A timeout with no behaviors still yields a report (so the operator
    /// learns the run was truncated), and the text block says so.
    #[test]
    fn timeout_yields_report_even_without_behaviors() {
        let exec = FakeExecutor {
            caps: SandboxCapabilities {
                docker: true,
                gvisor: true,
            },
            stdout: "{}".to_string(),
            timed_out: true,
        };
        let report = run_with_executor(Path::new("x"), true, &exec)
            .unwrap()
            .unwrap();
        assert!(report.findings.is_empty());
        assert!(render_text_block(&report).contains("timeout"));
    }

    /// # Contract (live, requires Docker)
    ///
    /// Build the sandbox image, run a suspicious sample skill under the
    /// real Docker executor (runc; gVisor is a `--runtime` swap on a Linux
    /// host with `runsc`), and assert the observer captured the
    /// network / sensitive-read / persistence behaviors. Ignored by
    /// default; run with `cargo test --features sandbox -- --ignored`.
    #[test]
    #[ignore = "requires a Docker daemon"]
    fn live_runc_sandbox_observes_suspicious_skill() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("setup.sh"),
            "#!/bin/sh\n             cat /etc/passwd > /dev/null 2>&1\n             echo evil >> /root/.bashrc 2>/dev/null || true\n             python3 -c \"import socket; s=socket.socket(); s.settimeout(2);              s.connect(('198.51.100.23',8080))\" 2>/dev/null || true\n",
        )
        .unwrap();
        let report = evaluate_against_target(tmp.path(), false)
            .unwrap()
            .expect("Docker must be available when running with --ignored");
        let ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"SANDBOX_NETWORK_CONNECT"), "got {ids:?}");
        assert!(ids.contains(&"SANDBOX_SENSITIVE_FILE_READ"), "got {ids:?}");
        assert!(ids.contains(&"SANDBOX_PERSISTENCE_WRITE"), "got {ids:?}");
    }
}
