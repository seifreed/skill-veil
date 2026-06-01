//! Sandbox executor: the only layer that touches a Docker daemon.
//!
//! Everything else in this module is pure and daemon-free. The
//! [`SandboxExecutor`] trait lets the channel be driven by a fake in
//! tests, while [`DockerExecutor`] is the production implementation that
//! shells out to `docker`. Capability detection lets the channel degrade
//! gracefully (skip, with a note) when Docker or the gVisor runtime is
//! absent, rather than failing the scan.

use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

/// What the host can provide for sandboxing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SandboxCapabilities {
    /// A Docker daemon is reachable.
    pub(crate) docker: bool,
    /// The gVisor `runsc` runtime is registered with the daemon.
    pub(crate) gvisor: bool,
}

/// Raw outcome of one container run.
#[derive(Debug, Clone)]
pub(crate) struct RawRun {
    pub(crate) stdout: String,
    pub(crate) timed_out: bool,
}

/// Drives container execution. Implemented by [`DockerExecutor`] in
/// production and by a fake in tests.
pub(crate) trait SandboxExecutor {
    fn capabilities(&self) -> SandboxCapabilities;
    /// Run `docker <docker_args>`, enforcing a wall-clock `timeout`, and
    /// return the captured stdout. The container is killed if it exceeds
    /// the timeout.
    fn run(&self, docker_args: &[String], timeout: Duration) -> Result<RawRun>;
}

/// Production executor that shells out to the host `docker` binary.
pub(crate) struct DockerExecutor;

impl DockerExecutor {
    fn unique_container_name() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("skill-veil-sbx-{}-{nanos}", std::process::id())
    }
}

impl SandboxExecutor for DockerExecutor {
    fn capabilities(&self) -> SandboxCapabilities {
        let docker = Command::new("docker")
            .arg("version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        let gvisor = docker
            && Command::new("docker")
                .args(["info", "--format", "{{.Runtimes}}"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("runsc"))
                .unwrap_or(false);
        SandboxCapabilities { docker, gvisor }
    }

    fn run(&self, docker_args: &[String], timeout: Duration) -> Result<RawRun> {
        // Name the container so a watcher thread can stop it on timeout.
        // Killing the `docker` CLI child alone would NOT stop the
        // container (it runs in the daemon), so an explicit `docker kill`
        // is the only correct way to enforce the wall-clock bound.
        let name = Self::unique_container_name();
        let mut args = docker_args.to_vec();
        let insert_at = args.iter().position(|a| a == "run").map_or(0, |i| i + 1);
        args.splice(insert_at..insert_at, ["--name".to_string(), name.clone()]);

        let (tx, rx) = mpsc::channel();
        let run_args = args.clone();
        thread::spawn(move || {
            let _ = tx.send(Command::new("docker").args(&run_args).output());
        });

        match rx.recv_timeout(timeout) {
            Ok(output) => {
                let output = output.context("spawning docker run")?;
                Ok(RawRun {
                    stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                    timed_out: false,
                })
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ = Command::new("docker").args(["kill", &name]).output();
                let stdout = rx
                    .recv()
                    .ok()
                    .and_then(Result::ok)
                    .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                    .unwrap_or_default();
                Ok(RawRun {
                    stdout,
                    timed_out: true,
                })
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                anyhow::bail!("docker run worker thread disconnected unexpectedly")
            }
        }
    }
}
