//! Volume / env_file classifiers shared by docker-compose finding,
//! capability and relation passes. Keeping the rules in one place keeps
//! finding output and capability output aligned: a volume that triggers
//! `MANIFEST_DOCKER_COMPOSE_HOST_MOUNT` MUST also escalate
//! `HostFilesystemAccess`, never one without the other.

/// Whether `volume` references the sensitive host root `root` either as a
/// bare anonymous volume (`/root`, `/root/.ssh`) or as a bind mount source
/// (`/root:/k`, `/root/.ssh:/k`).
///
/// A plain `volume.starts_with(root)` over-matches sibling stems —
/// `/rootfs`, `/processed`, `/system` would all spuriously land on
/// `/root`, `/proc`, `/sys` respectively. Requiring the next byte to be
/// either `/` or `:` reproduces the explicit-boundary semantics that
/// `/etc/` and `/var/run/docker.sock:` already encode literally.
pub(super) fn matches_root_path(volume: &str, root: &str) -> bool {
    if volume == root {
        return true;
    }
    if let Some(rest) = volume.strip_prefix(root) {
        return rest.starts_with('/') || rest.starts_with(':');
    }
    false
}

/// Whether a docker-compose `volumes` entry mounts a sensitive part of the host
/// filesystem (or the entire host root) into the container.
///
/// Relative bind mounts contained within the project (`./data:/data`,
/// `./logs:/var/log/app`) are NOT sensitive — they expose project-local data,
/// not host data. Only absolute mounts that target host-trust boundaries
/// (`/var/run/docker.sock`, `/etc`, `/proc`, `/sys`, `/root`, root `/:`,
/// `:/host` aliases, or any absolute `/X:/Y` bind mount) escalate the
/// `HostFilesystemAccess` / `FilesystemWrite` capabilities and the
/// `MANIFEST_DOCKER_COMPOSE_HOST_MOUNT` finding. This shared classifier
/// keeps the finding pass and the capability pass aligned — previously the
/// capability pass treated `./` mounts as host access, inflating
/// `effective_capabilities` and blast-radius factors.
pub(super) fn is_sensitive_host_volume(volume: &str) -> bool {
    volume.starts_with("/:")
        || volume.contains(":/host")
        || volume.starts_with("/var/run/docker.sock:")
        || volume.starts_with("/etc/")
        || matches_root_path(volume, "/root")
        || matches_root_path(volume, "/proc")
        || matches_root_path(volume, "/sys")
        || (volume.starts_with('/') && volume.contains(":/"))
}

/// Whether a docker-compose `env_file` value carries at least one usable path.
///
/// Schema permits a single string (`env_file: .env`) or a list of strings
/// (`env_file: [.env, .env.prod]`). `null`, empty string, empty list, or a
/// list of empty/whitespace strings carry no real environment file and must
/// NOT raise `MANIFEST_DOCKER_COMPOSE_ENV_FILE` or `SecretAccess`.
pub(super) fn env_file_has_real_paths(value: &serde_yaml::Value) -> bool {
    match value {
        serde_yaml::Value::String(s) => !s.trim().is_empty(),
        serde_yaml::Value::Sequence(seq) => seq
            .iter()
            .any(|item| item.as_str().is_some_and(|s| !s.trim().is_empty())),
        _ => false,
    }
}

/// Render a docker-compose `env_file` value as a clean comma-separated path
/// list. String shape returns the trimmed path; sequence shape joins the
/// non-empty entries with `, `. Used as `match_value` text — the previous
/// `format!("{:?}", env_file)` produced the YAML debug wrapper (`String("…")`)
/// which leaks internal types into audit output.
pub(super) fn render_env_file(value: &serde_yaml::Value) -> String {
    match value {
        serde_yaml::Value::String(s) => s.trim().to_string(),
        serde_yaml::Value::Sequence(seq) => seq
            .iter()
            .filter_map(|item| item.as_str().map(str::trim).filter(|s| !s.is_empty()))
            .collect::<Vec<_>>()
            .join(", "),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: `is_sensitive_host_volume` matches the sensitive root
    /// either bare (`/root`) or as a sub-path (`/root/.ssh`) and as a
    /// bind mount source (`/root:/k`, `/root/.ssh:/k`). The pre-fix
    /// `starts_with("/root")` over-matched sibling stems like `/rootfs`,
    /// `/processed`, `/system` because there was no boundary on the
    /// next byte after the root.
    #[test]
    fn matches_root_path_anchors_at_path_or_colon_boundary() {
        // Positive: bare anonymous volume, exact root.
        assert!(matches_root_path("/root", "/root"));
        // Positive: bare anonymous sub-path.
        assert!(matches_root_path("/root/.ssh", "/root"));
        // Positive: bind mount on the root.
        assert!(matches_root_path("/root:/k", "/root"));
        // Positive: bind mount on a sub-path of the root.
        assert!(matches_root_path("/root/.ssh:/k", "/root"));
        // Negative: sibling stem must NOT match.
        assert!(!matches_root_path("/rootfs", "/root"));
        assert!(!matches_root_path("/rootfs:/data", "/root"));
        assert!(!matches_root_path("/root_bak/x:/y", "/root"));
        // Same boundary semantics for /proc and /sys.
        assert!(matches_root_path("/proc:/proc", "/proc"));
        assert!(matches_root_path("/proc/1:/p1", "/proc"));
        assert!(!matches_root_path("/processed:/log", "/proc"));
        assert!(!matches_root_path("/proc-tools:/x", "/proc"));
        assert!(matches_root_path("/sys/kernel:/k", "/sys"));
        assert!(!matches_root_path("/system:/sys", "/sys"));
        assert!(!matches_root_path("/sysv:/x", "/sys"));
    }

    /// Contract: a bare anonymous YAML volume that shares a literal stem
    /// with `/root` (e.g. `/rootfs`) is NOT classified as a sensitive
    /// host mount. The bare-path branch was the only place where the
    /// pre-fix prefix-match caused a false positive in practice; the
    /// `:/...` form is also flagged via the catch-all "any absolute
    /// bind mount", so we explicitly exercise the bare form here to pin
    /// the boundary semantics.
    #[test]
    fn is_sensitive_host_volume_rejects_root_stem_lookalikes_bare() {
        assert!(!is_sensitive_host_volume("/rootfs"));
        assert!(!is_sensitive_host_volume("/rootkit"));
        assert!(!is_sensitive_host_volume("/processed"));
        assert!(!is_sensitive_host_volume("/sysv"));
    }
}
