//! Hardening policy for the dynamic-behavior sandbox.
//!
//! A [`SandboxPolicy`] encodes every isolation property the sandbox
//! guarantees and renders them into the exact `docker run` argument
//! vector the executor uses. Keeping the contract in one pure,
//! exhaustively-tested place means the security posture is verifiable
//! without a Docker daemon: the tests assert that the rendered command
//! drops all capabilities, runs under gVisor, mounts the skill
//! read-only, forbids privilege escalation, caps resources, and has no
//! network.
//!
//! # Threat model
//!
//! The sandbox runs UNTRUSTED code (a skill's scripts and an
//! instrumented agent). The host must be unaffected even if that code is
//! actively hostile. Defense in depth:
//!
//! - **gVisor (`runsc`)** intercepts syscalls in a user-space kernel, so
//!   a container escape must defeat gVisor rather than the host kernel
//!   directly. This is the primary boundary; the flags below are the
//!   secondary net.
//! - All Linux capabilities dropped, `no-new-privileges` set, and a
//!   non-root in-container user, so a process cannot gain privileges.
//! - Read-only root filesystem with a single `noexec,nosuid,nodev`
//!   tmpfs for scratch -- a written payload cannot be made executable.
//! - Resource caps (memory, CPU, PID count, open files) bound the blast
//!   radius of a fork bomb or memory exhaustion against the host.
//! - The skill under analysis is mounted read-only; nothing on the host
//!   is writable.
//! - Network disabled (`--network none`): the container reaches neither
//!   the host network nor the internet. Outbound attempts still fail
//!   observably (the in-container observer records the `connect()`), so
//!   exfil intent is captured without permitting the traffic. A
//!   recording-proxy mode (capture-and-block on an isolated bridge) is a
//!   planned follow-up and lands together with its proxy sidecar.
//!
//! gVisor is the recommended runtime. [`SandboxRuntime::Runc`] is
//! supported for hosts without gVisor but is explicitly weaker (shared
//! host kernel) and the executor surfaces that downgrade to the operator.

use std::path::PathBuf;

/// gVisor OCI runtime name as registered with the Docker daemon.
const GVISOR_RUNTIME: &str = "runsc";
/// In-container user -- `nobody:nogroup` on a standard base image. A high,
/// unprivileged uid/gid so a container-root compromise still maps to an
/// unprivileged host identity under userns remapping.
const SANDBOX_USER: &str = "65534:65534";
/// Mount point of the analysed skill inside the container (read-only).
const SKILL_MOUNT_TARGET: &str = "/skill";
const DEFAULT_IMAGE: &str = "skill-veil-sandbox:latest";
const DEFAULT_MEMORY_LIMIT: &str = "512m";
const DEFAULT_CPU_LIMIT: &str = "1.0";
const DEFAULT_PIDS_LIMIT: u32 = 256;
const DEFAULT_OPEN_FILES_LIMIT: u32 = 256;
const DEFAULT_TMPFS_SIZE: &str = "64m";
const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// Container runtime providing the isolation boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SandboxRuntime {
    /// gVisor user-space kernel (`runsc`). Recommended for untrusted code.
    Gvisor,
    /// Default Docker runtime (`runc`). Shares the host kernel -- weaker;
    /// use only when gVisor is unavailable and the host risk is accepted.
    Runc,
}

impl SandboxRuntime {
    /// The `--runtime` value, or `None` for the daemon default (`runc`).
    fn runtime_flag_value(self) -> Option<&'static str> {
        match self {
            SandboxRuntime::Gvisor => Some(GVISOR_RUNTIME),
            SandboxRuntime::Runc => None,
        }
    }
}

/// The full isolation contract for one sandbox run.
#[derive(Debug, Clone)]
pub(crate) struct SandboxPolicy {
    pub(crate) image: String,
    pub(crate) runtime: SandboxRuntime,
    pub(crate) skill_host_dir: PathBuf,
    pub(crate) memory_limit: String,
    pub(crate) cpu_limit: String,
    pub(crate) pids_limit: u32,
    pub(crate) open_files_limit: u32,
    pub(crate) tmpfs_size: String,
    pub(crate) timeout_secs: u64,
    /// Optional custom seccomp profile. When `None`, Docker's built-in
    /// restrictive default profile applies (never `unconfined`).
    pub(crate) seccomp_profile: Option<PathBuf>,
}

impl SandboxPolicy {
    /// Hardened defaults for analysing `skill_host_dir`: gVisor runtime,
    /// no network, all the isolation flags, conservative resource caps.
    pub(crate) fn hardened(skill_host_dir: PathBuf) -> Self {
        Self {
            image: DEFAULT_IMAGE.to_string(),
            runtime: SandboxRuntime::Gvisor,
            skill_host_dir,
            memory_limit: DEFAULT_MEMORY_LIMIT.to_string(),
            cpu_limit: DEFAULT_CPU_LIMIT.to_string(),
            pids_limit: DEFAULT_PIDS_LIMIT,
            open_files_limit: DEFAULT_OPEN_FILES_LIMIT,
            tmpfs_size: DEFAULT_TMPFS_SIZE.to_string(),
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            seccomp_profile: None,
        }
    }

    /// Render the policy into the `docker run` argument vector (the tokens
    /// that follow `docker`), appending `container_cmd` after the image as
    /// the in-container command. This is the single source of truth for
    /// the sandbox's isolation posture.
    pub(crate) fn to_docker_run_args(&self, container_cmd: &[String]) -> Vec<String> {
        let mut args: Vec<String> = vec!["run".into(), "--rm".into()];

        if let Some(runtime) = self.runtime.runtime_flag_value() {
            args.push("--runtime".into());
            args.push(runtime.into());
        }

        args.push("--network".into());
        args.push("none".into());
        args.push("--read-only".into());
        args.push("--tmpfs".into());
        args.push(format!(
            "/tmp:rw,noexec,nosuid,nodev,size={}",
            self.tmpfs_size
        ));
        args.push("--cap-drop".into());
        args.push("ALL".into());
        args.push("--security-opt".into());
        args.push("no-new-privileges".into());
        if let Some(profile) = &self.seccomp_profile {
            args.push("--security-opt".into());
            args.push(format!("seccomp={}", profile.display()));
        }
        args.push("--user".into());
        args.push(SANDBOX_USER.into());
        args.push("--memory".into());
        args.push(self.memory_limit.clone());
        args.push("--cpus".into());
        args.push(self.cpu_limit.clone());
        args.push("--pids-limit".into());
        args.push(self.pids_limit.to_string());
        args.push("--ulimit".into());
        args.push(format!(
            "nofile={}:{}",
            self.open_files_limit, self.open_files_limit
        ));
        args.push("--volume".into());
        args.push(format!(
            "{}:{SKILL_MOUNT_TARGET}:ro",
            self.skill_host_dir.display()
        ));
        args.push("--workdir".into());
        args.push(SKILL_MOUNT_TARGET.into());

        args.push(self.image.clone());
        args.extend(container_cmd.iter().cloned());
        args
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hardened() -> SandboxPolicy {
        SandboxPolicy::hardened(PathBuf::from("/host/skill"))
    }

    fn rendered() -> Vec<String> {
        hardened().to_docker_run_args(&["/observe".to_string()])
    }

    /// Returns the value token following the first occurrence of `flag`.
    fn value_after(args: &[String], flag: &str) -> Option<String> {
        args.iter()
            .position(|a| a == flag)
            .map(|i| args[i + 1].clone())
    }

    fn count(args: &[String], token: &str) -> usize {
        args.iter().filter(|a| a.as_str() == token).count()
    }

    /// # Contract
    /// The hardened policy runs under the gVisor runtime -- the primary
    /// isolation boundary for untrusted code.
    #[test]
    fn hardened_policy_uses_gvisor_runtime() {
        assert_eq!(
            value_after(&rendered(), "--runtime").as_deref(),
            Some("runsc")
        );
    }

    /// # Contract
    /// Every Linux capability is dropped; none is added back.
    #[test]
    fn hardened_policy_drops_all_capabilities() {
        let a = rendered();
        assert_eq!(value_after(&a, "--cap-drop").as_deref(), Some("ALL"));
        assert_eq!(count(&a, "--cap-add"), 0, "no capability may be added back");
    }

    /// # Contract
    /// Privilege escalation via setuid binaries is forbidden.
    #[test]
    fn hardened_policy_forbids_new_privileges() {
        assert!(rendered().iter().any(|a| a == "no-new-privileges"));
    }

    /// # Contract
    /// The container root filesystem is read-only and the only writable
    /// area is a `noexec,nosuid,nodev` tmpfs -- a dropped payload cannot be
    /// made executable.
    #[test]
    fn hardened_policy_root_is_read_only_and_tmpfs_is_noexec() {
        let a = rendered();
        assert!(a.iter().any(|x| x == "--read-only"));
        let tmpfs = value_after(&a, "--tmpfs").expect("tmpfs spec present");
        assert!(tmpfs.contains("noexec"), "tmpfs must be noexec: {tmpfs}");
        assert!(tmpfs.contains("nosuid"), "tmpfs must be nosuid: {tmpfs}");
        assert!(tmpfs.contains("nodev"), "tmpfs must be nodev: {tmpfs}");
    }

    /// # Contract
    /// The analysed skill is mounted READ-ONLY -- sandboxed code cannot
    /// write back to the host artifact.
    #[test]
    fn hardened_policy_mounts_skill_read_only() {
        let mount = value_after(&rendered(), "--volume").expect("volume present");
        assert!(
            mount.ends_with(":/skill:ro"),
            "skill mount must be read-only: {mount}"
        );
        assert!(mount.starts_with("/host/skill:"));
    }

    /// # Contract
    /// The container runs as a non-root, unprivileged user.
    #[test]
    fn hardened_policy_runs_as_non_root_user() {
        assert_eq!(
            value_after(&rendered(), "--user").as_deref(),
            Some("65534:65534")
        );
    }

    /// # Contract
    /// Resource caps (memory, CPU, PID count, open files) bound the host
    /// blast radius of resource-exhaustion attacks.
    #[test]
    fn hardened_policy_caps_resources() {
        let a = rendered();
        assert_eq!(value_after(&a, "--memory").as_deref(), Some("512m"));
        assert_eq!(value_after(&a, "--cpus").as_deref(), Some("1.0"));
        assert_eq!(value_after(&a, "--pids-limit").as_deref(), Some("256"));
        assert_eq!(
            value_after(&a, "--ulimit").as_deref(),
            Some("nofile=256:256")
        );
    }

    /// # Contract
    /// The container is removed after the run -- no residue accumulates on
    /// the host.
    #[test]
    fn hardened_policy_is_ephemeral() {
        assert!(rendered().iter().any(|a| a == "--rm"));
    }

    /// # Contract
    /// The hardened policy has no network connectivity.
    #[test]
    fn hardened_policy_disables_network() {
        assert_eq!(
            value_after(&rendered(), "--network").as_deref(),
            Some("none")
        );
    }

    /// # Contract
    /// A custom seccomp profile is wired when provided; otherwise the
    /// command never weakens to `seccomp=unconfined`.
    #[test]
    fn seccomp_profile_wired_only_when_present() {
        assert!(!rendered().iter().any(|a| a.contains("seccomp")));
        let mut policy = hardened();
        policy.seccomp_profile = Some(PathBuf::from("/etc/sv/seccomp.json"));
        let a = policy.to_docker_run_args(&[]);
        assert!(a.iter().any(|x| x == "seccomp=/etc/sv/seccomp.json"));
        assert!(
            !a.iter().any(|x| x.contains("unconfined")),
            "must never disable seccomp"
        );
    }

    /// # Contract (negative)
    /// The runc fallback omits the `--runtime` flag (daemon default) -- the
    /// rest of the hardening is identical, but the executor must warn that
    /// the kernel is shared.
    #[test]
    fn runc_runtime_omits_runtime_flag_but_keeps_hardening() {
        let mut policy = hardened();
        policy.runtime = SandboxRuntime::Runc;
        let a = policy.to_docker_run_args(&[]);
        assert_eq!(count(&a, "--runtime"), 0);
        assert_eq!(value_after(&a, "--cap-drop").as_deref(), Some("ALL"));
        assert!(a.iter().any(|x| x == "--read-only"));
        assert_eq!(value_after(&a, "--network").as_deref(), Some("none"));
    }

    /// # Contract
    /// The in-container command is appended after the image, in order.
    #[test]
    fn container_command_follows_image() {
        let policy = hardened();
        let a = policy.to_docker_run_args(&["/observe".to_string(), "--scripts".to_string()]);
        let image_idx = a
            .iter()
            .position(|x| x == &policy.image)
            .expect("image present");
        assert_eq!(a[image_idx + 1], "/observe");
        assert_eq!(a[image_idx + 2], "--scripts");
    }
}
