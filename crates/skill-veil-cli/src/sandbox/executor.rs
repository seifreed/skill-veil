//! Sandbox executor: the only layer that touches a Docker daemon.
//!
//! Everything else in this module is pure and daemon-free. The
//! [`SandboxExecutor`] trait lets the channel be driven by a fake in
//! tests, while [`DockerExecutor`] is the production implementation that
//! shells out to `docker`. Capability detection lets the channel degrade
//! gracefully (skip, with a note) when Docker or the gVisor runtime is
//! absent, rather than failing the scan.

use std::io::Write as _;
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

/// The sandbox container build context, embedded so `skill-veil` can
/// build the image on first use without shipping separate files.
const DOCKERFILE: &str = include_str!("image/Dockerfile");
const OBSERVE_PY: &str = include_str!("image/observe.py");
const PROXY_PY: &str = include_str!("image/proxy.py");
const GEN_CA_PY: &str = include_str!("image/gen_ca.py");

/// Repository name for the sandbox image. The concrete tag is derived
/// from the embedded build context's content hash (see
/// [`content_addressed_image_tag`]).
const IMAGE_REPO: &str = "skill-veil-sandbox";

/// Image tag derived from the SHA-256 of the embedded build context.
///
/// `ensure_image` only skips the build when *this* exact tag already
/// exists, so changing the Dockerfile, observer, or proxy yields a new
/// tag and forces a rebuild — a stale `:latest` can no longer mask an
/// updated build context. (The seccomp profile is a run-time
/// `--security-opt` artifact, never baked into the image, so it is
/// deliberately excluded from this hash.)
pub(crate) fn content_addressed_image_tag() -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for part in [DOCKERFILE, OBSERVE_PY, PROXY_PY, GEN_CA_PY] {
        hasher.update(part.as_bytes());
        hasher.update([0u8]);
    }
    let digest = hasher.finalize();
    format!("{IMAGE_REPO}:sv{}", hex::encode(&digest[..6]))
}

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

/// Outcome of a recorded run: the sandbox run plus the recording proxy's
/// raw capture log (one JSON object per intercepted request).
#[derive(Debug, Clone)]
pub(crate) struct RecordedRun {
    pub(crate) raw: RawRun,
    pub(crate) proxy_log: String,
}

/// Drives container execution. Implemented by [`DockerExecutor`] in
/// production and by a fake in tests.
pub(crate) trait SandboxExecutor {
    fn capabilities(&self) -> SandboxCapabilities;
    /// Ensure the sandbox image `tag` is available, building it from the
    /// embedded context if absent. Returns `true` when the image is ready.
    fn ensure_image(&self, tag: &str) -> Result<bool>;
    /// Run `docker <docker_args>`, enforcing a wall-clock `timeout`, and
    /// return the captured stdout. The container is killed if it exceeds
    /// the timeout.
    fn run(&self, docker_args: &[String], timeout: Duration) -> Result<RawRun>;
    /// Run `docker <sandbox_args>` on an isolated `--internal` network with
    /// a recording proxy reachable as `proxy_alias`, returning the run plus
    /// the proxy's capture log. The network and proxy are torn down even on
    /// failure.
    fn run_recorded(
        &self,
        sandbox_args: &[String],
        network: &str,
        proxy_alias: &str,
        image: &str,
        timeout: Duration,
    ) -> Result<RecordedRun>;
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

    fn ensure_image(&self, tag: &str) -> Result<bool> {
        let present = Command::new("docker")
            .args(["image", "inspect", tag])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if present {
            return Ok(true);
        }
        let context = tempfile::tempdir().context("creating sandbox image build context")?;
        write_file(context.path(), "Dockerfile", DOCKERFILE)?;
        write_file(context.path(), "observe.py", OBSERVE_PY)?;
        write_file(context.path(), "proxy.py", PROXY_PY)?;
        write_file(context.path(), "gen_ca.py", GEN_CA_PY)?;
        let status = Command::new("docker")
            .arg("build")
            .args(["-t", tag])
            .arg(context.path())
            .status()
            .context("running docker build for the sandbox image")?;
        Ok(status.success())
    }

    fn run(&self, docker_args: &[String], timeout: Duration) -> Result<RawRun> {
        self.spawn_and_wait(docker_args, timeout)
    }

    fn run_recorded(
        &self,
        sandbox_args: &[String],
        network: &str,
        proxy_alias: &str,
        image: &str,
        timeout: Duration,
    ) -> Result<RecordedRun> {
        let _ = Command::new("docker")
            .args(["network", "create", "--internal", network])
            .output()
            .context("creating isolated sandbox network")?;
        let proxy_name = format!("{network}-proxy");
        let proxy_started = Command::new("docker")
            .args(["run", "-d", "--rm", "--name", &proxy_name])
            .args(["--network", network, "--network-alias", proxy_alias])
            .args(["--user", "65534:65534", "--read-only", "--cap-drop", "ALL"])
            // The MITM proxy writes per-host leaf certs for `ssl.load_cert_chain`;
            // root is read-only, so give it a noexec scratch tmpfs.
            .args(["--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m"])
            .args([
                "--security-opt",
                "no-new-privileges",
                "--entrypoint",
                "python3",
            ])
            .arg(image)
            .arg("/proxy.py")
            .status()
            .context("starting recording proxy")?
            .success();
        // Give the proxy a moment to bind before the sandbox connects.
        if proxy_started {
            thread::sleep(Duration::from_millis(700));
        }
        let raw_result = self.spawn_and_wait(sandbox_args, timeout);
        let proxy_log = Command::new("docker")
            .args(["logs", &proxy_name])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        let _ = Command::new("docker")
            .args(["rm", "-f", &proxy_name])
            .output();
        let _ = Command::new("docker")
            .args(["network", "rm", network])
            .output();
        Ok(RecordedRun {
            raw: raw_result?,
            proxy_log,
        })
    }
}

impl DockerExecutor {
    fn spawn_and_wait(&self, docker_args: &[String], timeout: Duration) -> Result<RawRun> {
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

fn write_file(dir: &std::path::Path, name: &str, contents: &str) -> Result<()> {
    let path = dir.join(name);
    let mut file =
        std::fs::File::create(&path).with_context(|| format!("creating {}", path.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Contract
    /// The image tag is repository-scoped and derived from the embedded
    /// build context, so it is stable across calls and never the ambiguous
    /// `:latest` (which could mask a stale image).
    #[test]
    fn content_tag_is_stable_repo_scoped_and_not_latest() {
        let tag = content_addressed_image_tag();
        assert_eq!(tag, content_addressed_image_tag(), "must be deterministic");
        assert!(tag.starts_with("skill-veil-sandbox:sv"), "got {tag}");
        assert!(!tag.ends_with(":latest"));
        let hex = tag.strip_prefix("skill-veil-sandbox:sv").unwrap();
        assert_eq!(hex.len(), 12, "6 bytes of digest -> 12 hex chars: {hex}");
        assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    /// # Contract
    /// The tag is content-addressed: a different build context yields a
    /// different tag, which is what forces `ensure_image` to rebuild. This
    /// pins that all three embedded parts feed the hash.
    #[test]
    fn content_tag_changes_when_build_context_changes() {
        use sha2::{Digest, Sha256};
        let tag = content_addressed_image_tag();
        let mut hasher = Sha256::new();
        for part in [DOCKERFILE, OBSERVE_PY, PROXY_PY, GEN_CA_PY] {
            hasher.update(part.as_bytes());
            hasher.update([0u8]);
        }
        let expected = format!("{IMAGE_REPO}:sv{}", hex::encode(&hasher.finalize()[..6]));
        assert_eq!(tag, expected);

        let mut perturbed = Sha256::new();
        for part in [DOCKERFILE, OBSERVE_PY, PROXY_PY] {
            perturbed.update(part.as_bytes());
            perturbed.update([0u8]);
        }
        perturbed.update(b"different ca generator\0");
        let other = format!("{IMAGE_REPO}:sv{}", hex::encode(&perturbed.finalize()[..6]));
        assert_ne!(tag, other, "a changed CA generator must change the tag");
    }
}
