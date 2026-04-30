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
///
/// The docker socket is matched via `matches_root_path` rather than a bare
/// colon-anchored prefix because a manifest may mount the socket as an
/// **anonymous volume** (`- /var/run/docker.sock`, no target) — that form
/// also exposes the host docker daemon and must escalate the same
/// capabilities as the bind-mount form. Pre-fix this anonymous shape
/// slipped through both the colon-anchored docker.sock check and the
/// `:/`-requiring catch-all.
///
/// The source side of the entry is normalised before classification so
/// lexical aliases (`//var/run/docker.sock`, `/./var/run/docker.sock`)
/// cannot bypass detection: the docker engine collapses these to
/// `/var/run/docker.sock` at mount time, so an attacker can't use the
/// extra slashes to evade the literal-prefix branches while still
/// achieving full socket access in the running container.
pub(super) fn is_sensitive_host_volume(volume: &str) -> bool {
    let normalised = normalise_volume_for_classification(volume);
    let v = normalised.as_str();
    v.starts_with("/:")
        || destination_is_host_alias(v)
        || matches_root_path(v, "/var/run/docker.sock")
        || v.starts_with("/etc/")
        || matches_root_path(v, "/root")
        || matches_root_path(v, "/proc")
        || matches_root_path(v, "/sys")
        || (v.starts_with('/') && v.contains(":/"))
}

/// Collapse repeated slashes and `.` segments on the absolute SOURCE
/// side of a docker-compose volume entry so lexical bypasses
/// (`//var/run/docker.sock`, `/./var/run/docker.sock`) reduce to the
/// canonical `/var/run/docker.sock` before classification.
///
/// Only the source side (everything before the first `:`) is rewritten
/// — the target side is parsed by [`destination_is_host_alias`] which
/// has its own anchoring semantics. `..` segments are preserved
/// verbatim: the docker engine resolves them at mount time, so
/// collapsing them here would change classification semantics rather
/// than mirror the engine's behaviour. Relative sources (`./data`,
/// `db-data`) are returned unchanged since this normaliser only
/// operates on absolute host paths.
fn normalise_volume_for_classification(volume: &str) -> String {
    let (source, rest) = match volume.split_once(':') {
        Some((s, r)) => (s, Some(r)),
        None => (volume, None),
    };
    if !source.starts_with('/') {
        return volume.to_string();
    }
    let mut normalised = String::from("/");
    for segment in source
        .split('/')
        .filter(|seg| !seg.is_empty() && *seg != ".")
    {
        if normalised.len() > 1 {
            normalised.push('/');
        }
        normalised.push_str(segment);
    }
    match rest {
        Some(r) => format!("{normalised}:{r}"),
        None => normalised,
    }
}

/// Whether the destination of a bind-mount entry is the `/host` alias
/// (or a path under it). Pre-fix the gate was a bare
/// `volume.contains(":/host")` substring check, which spuriously
/// matched legitimate destinations like `/hostname`, `/host-backup`,
/// `/hostpath`. We now extract the destination explicitly (the segment
/// after the first `:`, before any trailing `:ro` / `:rw` flag) and
/// require an exact `/host` match or a `/host/` sub-path.
fn destination_is_host_alias(volume: &str) -> bool {
    let Some((_source, rest)) = volume.split_once(':') else {
        return false;
    };
    let destination = rest.split(':').next().unwrap_or(rest);
    destination == "/host" || destination.starts_with("/host/")
}

/// Render a docker-compose `volumes` entry as the equivalent
/// `SOURCE[:TARGET]` string suitable for [`is_sensitive_host_volume`].
///
/// docker-compose accepts two volume shapes:
///
/// - **Short syntax** — a string like `"/etc:/host-etc:ro"` or
///   `"./data:/data"`. Returned verbatim.
/// - **Long syntax** — a mapping like
///   `{type: bind, source: /etc, target: /host-etc}`. Pre-fix the
///   classifier silently dropped these entries via
///   `.filter_map(Value::as_str)`, so a malicious manifest could mount
///   the docker socket using long syntax and bypass both
///   `MANIFEST_DOCKER_COMPOSE_HOST_MOUNT` and the
///   `HostFilesystemAccess` capability. We now synthesise the
///   equivalent `source:target` string so the existing classifier
///   covers both shapes.
///
/// Returns `None` for:
///
/// - Long-syntax entries whose `type` is anything other than `bind`
///   (named volumes, `tmpfs`, `npipe`, `cluster`) — those never expose
///   a host path, so classifying them is meaningless.
/// - Long-syntax entries without a `source` field.
/// - Anything that is neither a string nor a mapping (e.g. the YAML
///   `null` literal).
pub(super) fn volume_entry_string(value: &serde_yaml::Value) -> Option<String> {
    match value {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Mapping(map) => {
            let kind = map
                .get(serde_yaml::Value::String("type".to_string()))
                .and_then(serde_yaml::Value::as_str);
            // `bind` is the only mount type that exposes a host path.
            // The default when `type` is omitted is also `bind` per
            // the compose spec when `source` is absolute, so we accept
            // both `Some("bind")` and `None`.
            if matches!(kind, Some(other) if other != "bind") {
                return None;
            }
            let source = map
                .get(serde_yaml::Value::String("source".to_string()))
                .and_then(serde_yaml::Value::as_str)?;
            let target = map
                .get(serde_yaml::Value::String("target".to_string()))
                .and_then(serde_yaml::Value::as_str);
            Some(match target {
                Some(target) => format!("{source}:{target}"),
                None => source.to_string(),
            })
        }
        _ => None,
    }
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

    /// Contract: a bare anonymous mount of `/var/run/docker.sock`
    /// (no `:target` and no `:/` catch-all) MUST be classified as
    /// sensitive. Pre-fix `volume.starts_with("/var/run/docker.sock:")`
    /// required the colon-prefix and the `(starts_with('/') && contains(":/"))`
    /// catch-all required `:/`, so a manifest like
    /// `volumes: [- /var/run/docker.sock]` (valid anonymous-volume
    /// syntax in compose) escaped both branches and bypassed
    /// `MANIFEST_DOCKER_COMPOSE_HOST_MOUNT` plus the
    /// `HostFilesystemAccess` capability.
    #[test]
    fn is_sensitive_host_volume_flags_bare_anonymous_docker_socket_mount() {
        // Positive: bare anonymous socket mount.
        assert!(is_sensitive_host_volume("/var/run/docker.sock"));
        // Positive: traditional bind-mount form is still classified.
        assert!(is_sensitive_host_volume("/var/run/docker.sock:/sock"));
        assert!(is_sensitive_host_volume(
            "/var/run/docker.sock:/var/run/docker.sock:ro"
        ));
        // Negative: sibling stems on the docker.sock prefix MUST NOT
        // match — `/var/run/docker.sockd` is a hypothetical sibling
        // path, not the socket. Pin the boundary semantics so a future
        // refactor that swaps back to `starts_with` regresses here.
        assert!(!is_sensitive_host_volume("/var/run/docker.sockd"));
        assert!(!is_sensitive_host_volume("/var/run/docker.sock-bak"));
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

    /// Contract: the `:/host` alias is matched by destination-boundary,
    /// not by raw substring. Pre-fix `volume.contains(":/host")` falsely
    /// flagged any destination whose name simply *began* with `host`
    /// (e.g. `/hostname`, `/host-backup`, `/hostpath`), inflating
    /// `HostFilesystemAccess` and emitting bogus
    /// `MANIFEST_DOCKER_COMPOSE_HOST_MOUNT` findings on legitimate
    /// project-relative mounts.
    #[test]
    fn destination_is_host_alias_requires_exact_or_subpath_boundary() {
        // Positive: exact `/host` destination, with and without an
        // optional mount-mode flag.
        assert!(destination_is_host_alias("./data:/host"));
        assert!(destination_is_host_alias("./data:/host:ro"));
        assert!(destination_is_host_alias("/srv:/host:rw"));
        // Positive: sub-path under `/host` (still the host alias root).
        assert!(destination_is_host_alias("./data:/host/etc"));
        assert!(destination_is_host_alias("./data:/host/data:ro"));
        // Negative: sibling stems whose destination merely *starts* with
        // the four bytes `host` MUST NOT match.
        assert!(!destination_is_host_alias("./data:/hostname"));
        assert!(!destination_is_host_alias("./data:/host-backup"));
        assert!(!destination_is_host_alias("./data:/hostpath"));
        assert!(!destination_is_host_alias("./data:/host_data:ro"));
        // Negative: anonymous volumes (no `:`) carry no destination.
        assert!(!destination_is_host_alias("/data"));
    }

    /// Contract: `is_sensitive_host_volume` rejects `:/host*` lookalikes
    /// that share a stem with the alias but are not `/host` itself.
    /// Pins the bug-2 fix end-to-end so the boundary regression is
    /// caught at the public-classifier level, not just in the helper.
    #[test]
    fn is_sensitive_host_volume_rejects_host_alias_lookalikes() {
        assert!(!is_sensitive_host_volume("./data:/hostname"));
        assert!(!is_sensitive_host_volume("./data:/host-backup"));
        assert!(!is_sensitive_host_volume("./data:/hostpath"));
        // Positive case still fires for the actual alias.
        assert!(is_sensitive_host_volume("./data:/host"));
        assert!(is_sensitive_host_volume("./data:/host/etc"));
    }

    /// Contract: `volume_entry_string` accepts both docker-compose
    /// volume shapes — short (string) and long (mapping) — so the
    /// classifier sees them uniformly. Pre-fix `detect_host_volumes`
    /// used `.filter_map(Value::as_str)`, silently dropping every
    /// long-syntax entry. A malicious manifest could therefore mount
    /// the docker socket via
    /// `{type: bind, source: /var/run/docker.sock, target: ...}` and
    /// bypass `MANIFEST_DOCKER_COMPOSE_HOST_MOUNT` *and*
    /// `HostFilesystemAccess`.
    #[test]
    fn volume_entry_string_returns_string_form_for_short_syntax() {
        let value = serde_yaml::Value::String("/etc:/host-etc".to_string());
        assert_eq!(
            volume_entry_string(&value).as_deref(),
            Some("/etc:/host-etc"),
        );
    }

    #[test]
    fn volume_entry_string_synthesises_source_target_for_long_bind_syntax() {
        let yaml = "type: bind\nsource: /var/run/docker.sock\ntarget: /sock\n";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).expect("valid yaml");
        assert_eq!(
            volume_entry_string(&value).as_deref(),
            Some("/var/run/docker.sock:/sock"),
        );
    }

    /// Contract: when `type` is omitted from the long-syntax mapping,
    /// docker-compose treats it as `bind` if `source` is absolute. We
    /// must classify these too so an attacker can't strip the `type`
    /// field to evade detection.
    #[test]
    fn volume_entry_string_accepts_long_syntax_without_explicit_type() {
        let yaml = "source: /etc\ntarget: /host-etc\n";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).expect("valid yaml");
        assert_eq!(
            volume_entry_string(&value).as_deref(),
            Some("/etc:/host-etc"),
        );
    }

    /// Contract: long-syntax entries whose `type` is anything other
    /// than `bind` (named `volume`, `tmpfs`, `npipe`, `cluster`) carry
    /// no host path and MUST NOT be classified as sensitive — we
    /// return `None` so they are skipped in the upstream filter chain.
    #[test]
    fn volume_entry_string_skips_non_bind_long_syntax() {
        for kind in ["volume", "tmpfs", "npipe", "cluster"] {
            let yaml = format!("type: {kind}\nsource: db-data\ntarget: /var/lib/db\n");
            let value: serde_yaml::Value = serde_yaml::from_str(&yaml).expect("valid yaml");
            assert!(
                volume_entry_string(&value).is_none(),
                "type={kind} must yield None; got {:?}",
                volume_entry_string(&value),
            );
        }
    }

    /// Contract: a bare anonymous mount whose source carries a leading
    /// duplicate slash (`//var/run/docker.sock`) or an embedded `/./`
    /// segment (`/./var/run/docker.sock`) MUST still be classified as
    /// sensitive. Pre-fix `matches_root_path` did a bare `strip_prefix`
    /// that failed on `//var/...`, and the catch-all required `:/` —
    /// so an attacker could ship an anonymous-volume entry with a
    /// double slash and bypass `MANIFEST_DOCKER_COMPOSE_HOST_MOUNT`
    /// while the docker engine collapsed the path to the real socket
    /// at mount time.
    #[test]
    fn is_sensitive_host_volume_flags_lexically_aliased_anonymous_socket_mount() {
        // Leading double slash — POSIX sometimes preserves it but
        // docker engine collapses it; classification must too.
        assert!(is_sensitive_host_volume("//var/run/docker.sock"));
        // `/./` segment — same canonical destination, same risk.
        assert!(is_sensitive_host_volume("/./var/run/docker.sock"));
        // Triple slash run mid-path.
        assert!(is_sensitive_host_volume("/var//run/docker.sock"));
        // Combined alias forms still classify.
        assert!(is_sensitive_host_volume("//./var/run/docker.sock"));
        // Same aliasing on /etc must still reach the `/etc/` branch.
        assert!(is_sensitive_host_volume("//etc/passwd:/k"));
        assert!(is_sensitive_host_volume("/./etc/shadow:/k"));
        // Same aliasing on /root anonymous mount.
        assert!(is_sensitive_host_volume("//root/.ssh"));
        assert!(is_sensitive_host_volume("/./root/.ssh/authorized_keys"));
    }

    /// Contract: the source-side normaliser rewrites only the segment
    /// before the first `:` and leaves the target side untouched, so
    /// downstream `destination_is_host_alias` parsing is not affected
    /// by the new normalisation pass. Relative sources are returned
    /// verbatim.
    #[test]
    fn normalise_volume_for_classification_only_rewrites_absolute_source() {
        assert_eq!(
            normalise_volume_for_classification("//var/run/docker.sock"),
            "/var/run/docker.sock"
        );
        assert_eq!(
            normalise_volume_for_classification("/./etc:/host-etc:ro"),
            "/etc:/host-etc:ro"
        );
        // Relative source: untouched.
        assert_eq!(
            normalise_volume_for_classification("./data:/data"),
            "./data:/data"
        );
        // Named volume: untouched.
        assert_eq!(
            normalise_volume_for_classification("db-data:/var/lib/db"),
            "db-data:/var/lib/db"
        );
        // `..` segments are preserved (docker engine resolves them).
        assert_eq!(
            normalise_volume_for_classification("/foo/../bar"),
            "/foo/../bar"
        );
    }

    /// Contract: end-to-end the long-syntax bind mount of
    /// `/var/run/docker.sock` MUST be classified as a sensitive host
    /// mount. Pins the bug-1 fix at the public-classifier level — the
    /// pre-fix code returned `false` because `as_str()` filtered the
    /// entry out before it ever reached `is_sensitive_host_volume`.
    #[test]
    fn long_syntax_bind_mount_of_docker_socket_is_classified_as_sensitive() {
        let yaml = "type: bind\nsource: /var/run/docker.sock\ntarget: /var/run/docker.sock\n";
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).expect("valid yaml");
        let entry = volume_entry_string(&value).expect("bind volume must yield a string");
        assert!(
            is_sensitive_host_volume(&entry),
            "long-syntax docker-socket bind mount must be classified as sensitive; got entry={entry:?}",
        );
    }
}
