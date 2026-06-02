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
/// Agent-detonation build context: the agent image bundles a real coding
/// agent (OpenCode) that USES the skill so gated malicious paths execute.
const AGENT_DOCKERFILE: &str = include_str!("image/Dockerfile.agent");
const DETONATE_PY: &str = include_str!("image/detonate.py");

/// Repository name for the sandbox image. The concrete tag is derived
/// from the embedded build context's content hash (see
/// [`content_addressed_image_tag`]).
const IMAGE_REPO: &str = "skill-veil-sandbox";

/// Hosts the agent-detonation proxy forwards (the OpenCode agent's own
/// model gateway and startup fetches). Everything NOT on this list is the
/// skill-under-analysis's traffic and is captured + blocked.
const AGENT_PROXY_ALLOWLIST: &str =
    "opencode.ai,models.dev,github.com,registry.npmjs.org,githubusercontent.com";

/// Port the recording proxy listens on (matches `proxy.py`'s default).
const PROXY_PORT: u16 = 8080;

/// `docker inspect` Go template yielding the container's IPv4 on its
/// (single) attached network.
const CONTAINER_IP_TEMPLATE: &str = "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}";

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

/// Content-addressed tag for the agent-detonation image (separate repo so
/// the lean observer image is never bloated with the agent toolchain).
pub(crate) fn agent_image_tag() -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for part in [
        AGENT_DOCKERFILE,
        OBSERVE_PY,
        PROXY_PY,
        GEN_CA_PY,
        DETONATE_PY,
    ] {
        hasher.update(part.as_bytes());
        hasher.update([0u8]);
    }
    let digest = hasher.finalize();
    format!("{IMAGE_REPO}-agent:sv{}", hex::encode(&digest[..6]))
}

/// The hosts the agent-detonation proxy forwards to the real upstream.
pub(crate) fn agent_proxy_allowlist() -> &'static str {
    AGENT_PROXY_ALLOWLIST
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

/// Outcome of an agent-detonation run: the run, the selective proxy's
/// capture log (the skill's blocked egress; the agent's allowlisted egress
/// is forwarded silently and never logged), and the proxy's IP so the
/// caller can drop the agent→proxy hops from the observed behaviors.
#[derive(Debug, Clone)]
pub(crate) struct DetonationRun {
    pub(crate) raw: RawRun,
    pub(crate) proxy_log: String,
    pub(crate) proxy_ip: Option<String>,
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
    /// Ensure the agent-detonation image `tag` is available. Default: not
    /// available (only [`DockerExecutor`] builds it).
    fn ensure_agent_image(&self, _tag: &str) -> Result<bool> {
        Ok(false)
    }
    /// Run an agent-detonation: a dual-homed selective proxy (allowlist
    /// forwarded, everything else captured + blocked) plus the sandboxed
    /// agent container that detonates the skill. Default: unsupported.
    fn run_agent_detonation(
        &self,
        _sandbox_args: &[String],
        _network: &str,
        _proxy_alias: &str,
        _image: &str,
        _allowlist: &str,
        _timeout: Duration,
    ) -> Result<DetonationRun> {
        anyhow::bail!("agent detonation is not supported by this executor")
    }
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

    fn ensure_agent_image(&self, tag: &str) -> Result<bool> {
        let present = Command::new("docker")
            .args(["image", "inspect", tag])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if present {
            return Ok(true);
        }
        let context = tempfile::tempdir().context("creating agent image build context")?;
        write_file(context.path(), "Dockerfile", AGENT_DOCKERFILE)?;
        write_file(context.path(), "observe.py", OBSERVE_PY)?;
        write_file(context.path(), "proxy.py", PROXY_PY)?;
        write_file(context.path(), "gen_ca.py", GEN_CA_PY)?;
        write_file(context.path(), "detonate.py", DETONATE_PY)?;
        // `--network host` so the OpenCode installer's downloads resolve
        // even where the build sandbox's DNS is broken (e.g. some BuildKit
        // hosts); the build still runs in the daemon, not the sandbox.
        let status = Command::new("docker")
            .arg("build")
            .args(["--network", "host"])
            .args(["-t", tag])
            .arg(context.path())
            .status()
            .context("running docker build for the agent image")?;
        Ok(status.success())
    }

    fn run(&self, docker_args: &[String], timeout: Duration) -> Result<RawRun> {
        self.spawn_and_wait(docker_args, timeout)
    }

    fn run_agent_detonation(
        &self,
        sandbox_args: &[String],
        network: &str,
        proxy_alias: &str,
        image: &str,
        allowlist: &str,
        timeout: Duration,
    ) -> Result<DetonationRun> {
        let egress = format!("{network}-egress");
        let _ = Command::new("docker")
            .args(["network", "create", "--internal", network])
            .output()
            .context("creating isolated detonation network")?;
        let _ = Command::new("docker")
            .args(["network", "create", &egress])
            .output()
            .context("creating detonation egress network")?;
        let proxy_name = format!("{network}-proxy");
        let proxy_started = Command::new("docker")
            .args(["run", "-d", "--rm", "--name", &proxy_name])
            .args(["--network", network, "--network-alias", proxy_alias])
            .args(["--user", "65534:65534", "--read-only", "--cap-drop", "ALL"])
            .args(["--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=32m"])
            .args(["--security-opt", "no-new-privileges"])
            .args(["--env", &format!("SV_PROXY_ALLOWLIST={allowlist}")])
            .args(["--entrypoint", "python3"])
            .arg(image)
            .arg("/proxy.py")
            .status()
            .context("starting selective detonation proxy")?
            .success();
        // Dual-home the proxy: a second interface with real egress so it
        // can forward the allowlisted hosts upstream. The sandbox stays on
        // the `--internal` net and can reach the internet ONLY through it.
        let _ = Command::new("docker")
            .args(["network", "connect", &egress, &proxy_name])
            .output();

        let mut proxy_ip = None;
        let mut args = sandbox_args.to_vec();
        if proxy_started {
            thread::sleep(Duration::from_millis(1500));
            proxy_ip = container_ip_on(&proxy_name, network);
            if let Some(ip) = &proxy_ip {
                let url = format!("http://{ip}:{PROXY_PORT}");
                let insert_at = args.iter().position(|a| a == "run").map_or(0, |i| i + 1);
                args.splice(
                    insert_at..insert_at,
                    [
                        "--env".to_string(),
                        format!("HTTP_PROXY={url}"),
                        "--env".to_string(),
                        format!("HTTPS_PROXY={url}"),
                    ],
                );
            }
        }
        let raw_result = self.spawn_and_wait(&args, timeout);
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
        let _ = Command::new("docker")
            .args(["network", "rm", &egress])
            .output();
        Ok(DetonationRun {
            raw: raw_result?,
            proxy_log,
            proxy_ip,
        })
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
        // Point the sandbox's *_PROXY env at the proxy's IP rather than a
        // network alias: under gVisor's netstack the container cannot reach
        // Docker's embedded DNS resolver, so an alias would not resolve and
        // the proxy would silently capture nothing. The IP is known only
        // after the proxy container starts, which is why the policy leaves
        // the proxy env to the executor.
        let mut sandbox_args = sandbox_args.to_vec();
        if proxy_started {
            // Give the proxy a moment to bind before the sandbox connects.
            thread::sleep(Duration::from_millis(700));
            if let Some(ip) = container_ip(&proxy_name) {
                let url = format!("http://{ip}:{PROXY_PORT}");
                let insert_at = sandbox_args
                    .iter()
                    .position(|a| a == "run")
                    .map_or(0, |i| i + 1);
                sandbox_args.splice(
                    insert_at..insert_at,
                    [
                        "--env".to_string(),
                        format!("HTTP_PROXY={url}"),
                        "--env".to_string(),
                        format!("HTTPS_PROXY={url}"),
                    ],
                );
            }
        }
        let raw_result = self.spawn_and_wait(&sandbox_args, timeout);
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

/// The container's IPv4 on its attached network, or `None` if it cannot
/// be determined (the recorded run then proceeds with no proxy env: on the
/// `--internal` network outbound attempts simply fail, observably).
fn container_ip(name: &str) -> Option<String> {
    let output = Command::new("docker")
        .args(["inspect", "-f", CONTAINER_IP_TEMPLATE, name])
        .output()
        .ok()?;
    let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!ip.is_empty()).then_some(ip)
}

/// The container's IPv4 on a SPECIFIC network. The detonation proxy is
/// dual-homed (sandbox net + egress net), so the sandbox must be pointed
/// at the proxy's address on the *sandbox* net, not whichever a `range`
/// happens to yield first.
fn container_ip_on(name: &str, network: &str) -> Option<String> {
    let template = format!(r#"{{{{(index .NetworkSettings.Networks "{network}").IPAddress}}}}"#);
    let output = Command::new("docker")
        .args(["inspect", "-f", &template, name])
        .output()
        .ok()?;
    let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!ip.is_empty()).then_some(ip)
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

    /// # Contract
    /// The agent-detonation image is a SEPARATE, content-addressed repo
    /// (`skill-veil-sandbox-agent`) so the lean observer image is never
    /// bloated with the agent toolchain, and its tag differs from the
    /// observer image's.
    #[test]
    fn agent_image_tag_is_separate_repo_and_distinct() {
        let agent = agent_image_tag();
        assert_eq!(agent, agent_image_tag(), "deterministic");
        assert!(
            agent.starts_with("skill-veil-sandbox-agent:sv"),
            "got {agent}"
        );
        assert_ne!(agent, content_addressed_image_tag());
        assert!(agent_proxy_allowlist().contains("opencode.ai"));
    }
}
