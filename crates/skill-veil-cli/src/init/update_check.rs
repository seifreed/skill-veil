//! Best-effort startup check that asks GitHub whether either rule
//! source has a newer head than the locally installed pin.
//!
//! Designed to be CI-safe: only emits a single line on stderr,
//! never blocks the scan, never fails (network errors degrade
//! silently to "no update info"), and self-rate-limits via a
//! 24-hour timestamp marker in `<cache>/last-update-check`.
//!
//! Operator overrides:
//! - `SKILL_VEIL_NO_UPDATE_CHECK=1` — skip entirely.
//! - `--no-update-check` flag (passed through `Behaviour::Skipped`).
//! - The TTL can be widened via `SKILL_VEIL_UPDATE_CHECK_TTL_SECS`
//!   (env-only, no flag — this is power-user territory).

use anyhow::Result;
use std::fs::Metadata;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_TTL_SECS: u64 = 24 * 60 * 60;
const ENV_DISABLE: &str = "SKILL_VEIL_NO_UPDATE_CHECK";
const ENV_TTL: &str = "SKILL_VEIL_UPDATE_CHECK_TTL_SECS";
const HTTP_TIMEOUT_SECS: u64 = 8;
const MARKER_FILENAME: &str = "last-update-check";
const MAX_UPDATE_JSON_BYTES: u64 = 1024 * 1024;

/// What the operator chose for this scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Behaviour {
    /// Default: notify if a newer version exists; never prompt; never
    /// block. The check is skipped if a marker file says we already
    /// looked within the TTL.
    Notify,
    /// `--no-update-check`: don't even hit the network.
    Skipped,
}

/// Run the check and emit a one-line stderr hint if newer rule sources
/// are available. The function always returns `Ok(())`; failures
/// degrade silently (we deliberately do NOT error a scan because the
/// update notifier had a network blip).
pub(crate) fn maybe_notify(
    behaviour: Behaviour,
    cache_root: &Path,
    skill_veil_installed: Option<&str>,
    nova_installed_sha: Option<&str>,
) {
    if matches!(behaviour, Behaviour::Skipped) {
        return;
    }
    if std::env::var(ENV_DISABLE).is_ok() {
        return;
    }
    let ttl = ttl_from_env();
    let marker = cache_root.join(MARKER_FILENAME);
    if recently_checked(&marker, ttl) {
        return;
    }
    // Best-effort touch FIRST, so a recurring transient failure
    // does not hammer GitHub on every scan.
    let _ = touch_marker(&marker);

    let sv_latest = latest_skill_veil_release_tag().ok();
    let nova_latest = latest_nova_sha().ok();

    let mut notes: Vec<String> = Vec::new();
    if let (Some(installed), Some(latest)) = (skill_veil_installed, sv_latest.as_deref()) {
        if installed != latest {
            notes.push(format!(
                "skill-veil-rules: installed {installed}, latest {latest} \
                 (run: skill-veil rules update)"
            ));
        }
    }
    if let (Some(installed), Some(latest)) = (nova_installed_sha, nova_latest.as_deref()) {
        if installed != latest {
            notes.push(format!(
                "nova-rules: installed {short}, latest {short_latest} \
                 (run: skill-veil rules update)",
                short = short_sha(installed),
                short_latest = short_sha(latest),
            ));
        }
    }

    if !notes.is_empty() {
        eprintln!("[skill-veil] update available:");
        for note in notes {
            eprintln!("  - {note}");
        }
    }
}

fn ttl_from_env() -> Duration {
    std::env::var(ENV_TTL)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map_or(Duration::from_secs(DEFAULT_TTL_SECS), Duration::from_secs)
}

fn recently_checked(marker: &Path, ttl: Duration) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(marker) else {
        return false;
    };
    if !meta.is_file() || meta.file_type().is_symlink() {
        return false;
    }
    if !has_single_hardlink(&meta) {
        return false;
    }
    let Ok(modified) = meta.modified() else {
        return false;
    };
    let Ok(age) = SystemTime::now().duration_since(modified) else {
        return false;
    };
    age < ttl
}

fn touch_marker(marker: &Path) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    crate::util::cache_io::write_cache_file_atomic(marker, now.to_string().as_bytes())?;
    Ok(())
}

fn latest_skill_veil_release_tag() -> Result<String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .redirects(0)
        .build();
    let resp = agent
        .get("https://github.com/seifreed/skill-veil-rules/releases/latest")
        .set(
            "User-Agent",
            concat!("skill-veil/", env!("CARGO_PKG_VERSION"), " (+update-check)"),
        )
        .call();
    let location = match resp {
        Ok(r) => r.header("location").map(str::to_string),
        Err(ureq::Error::Status(_, r)) => r.header("location").map(str::to_string),
        Err(_) => return Err(anyhow::anyhow!("transport error")),
    };
    let location = location.ok_or_else(|| anyhow::anyhow!("no Location header"))?;
    let tag = location
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("could not parse tag from redirect"))?
        .to_string();
    validate_release_tag(&tag)?;
    Ok(tag)
}

fn latest_nova_sha() -> Result<String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .build();
    let resp = agent
        .get("https://api.github.com/repos/Nova-Hunting/nova-rules/commits/HEAD")
        .set(
            "User-Agent",
            concat!("skill-veil/", env!("CARGO_PKG_VERSION"), " (+update-check)"),
        )
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| anyhow::anyhow!("HTTP error: {e}"))?;
    let body = read_string_bounded(resp.into_reader(), MAX_UPDATE_JSON_BYTES)?;
    let v: serde_json::Value = serde_json::from_str(&body)?;
    let sha = v
        .get("sha")
        .and_then(|s| s.as_str())
        .ok_or_else(|| anyhow::anyhow!("no sha field in commit response"))?;
    validate_nova_sha(sha)?;
    Ok(sha.to_string())
}

fn validate_release_tag(tag: &str) -> Result<()> {
    let bytes = tag.as_bytes();
    if !bytes.is_empty()
        && bytes[0] == b'v'
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        Ok(())
    } else {
        anyhow::bail!("unexpected skill-veil-rules release tag shape")
    }
}

fn validate_nova_sha(sha: &str) -> Result<()> {
    if sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        anyhow::bail!("unexpected NOVA commit SHA shape")
    }
}

fn read_string_bounded(reader: impl Read, cap: u64) -> Result<String> {
    let mut body = String::new();
    reader
        .take(cap.saturating_add(1))
        .read_to_string(&mut body)?;
    if body.len() as u64 > cap {
        anyhow::bail!("GitHub update response exceeded {cap} bytes")
    }
    Ok(body)
}

fn short_sha(sha: &str) -> String {
    sha.chars().take(7).collect()
}

#[cfg(unix)]
fn has_single_hardlink(meta: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.nlink() == 1
}

#[cfg(not(unix))]
fn has_single_hardlink(_meta: &Metadata) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: `--no-update-check` (Behaviour::Skipped) bypasses
    /// every code path, including the marker touch. Otherwise a
    /// CI run with `--no-update-check` would still write to the
    /// cache.
    #[test]
    fn skipped_behaviour_does_nothing() {
        let dir = tempfile::TempDir::new().unwrap();
        maybe_notify(
            Behaviour::Skipped,
            dir.path(),
            Some("v0.1.0"),
            Some("deadbeef"),
        );
        let marker = dir.path().join(MARKER_FILENAME);
        assert!(!marker.exists(), "marker MUST NOT be touched when skipped");
    }

    /// Contract: `SKILL_VEIL_NO_UPDATE_CHECK=1` short-circuits even
    /// when the caller passed `Behaviour::Notify`. Operators in
    /// air-gapped environments rely on this to silence the
    /// notifier without changing the CLI invocation.
    #[test]
    fn env_disable_short_circuits_notify() {
        let dir = tempfile::TempDir::new().unwrap();
        std::env::set_var(ENV_DISABLE, "1");
        maybe_notify(
            Behaviour::Notify,
            dir.path(),
            Some("v0.1.0"),
            Some("deadbeef"),
        );
        std::env::remove_var(ENV_DISABLE);
        let marker = dir.path().join(MARKER_FILENAME);
        assert!(!marker.exists());
    }

    /// Contract: the marker file is honoured. Two consecutive calls
    /// inside the TTL must not both hit the network. We can't easily
    /// inject a clock, so we simulate by touching the marker first
    /// and then asserting `recently_checked` returns true.
    #[test]
    fn marker_file_within_ttl_is_recent() {
        let dir = tempfile::TempDir::new().unwrap();
        let marker = dir.path().join(MARKER_FILENAME);
        touch_marker(&marker).unwrap();
        assert!(recently_checked(&marker, Duration::from_secs(60 * 60)));
    }

    /// Contract: a marker older than TTL is NOT considered recent —
    /// otherwise the daily check would silently never re-run after
    /// the first ever invocation. Use a very small TTL to keep the
    /// test fast.
    #[test]
    fn marker_file_past_ttl_is_not_recent() {
        let dir = tempfile::TempDir::new().unwrap();
        let marker = dir.path().join(MARKER_FILENAME);
        touch_marker(&marker).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert!(!recently_checked(&marker, Duration::from_millis(10)));
    }

    /// # Contract
    ///
    /// A symlinked update-check marker is not authoritative state. It
    /// must not suppress the update check by borrowing the target's
    /// timestamp.
    #[cfg(unix)]
    #[test]
    fn symlink_marker_is_not_recent() {
        let dir = tempfile::TempDir::new().unwrap();
        let target = dir.path().join("target-marker");
        let marker = dir.path().join(MARKER_FILENAME);
        std::fs::write(&target, b"recent").unwrap();
        std::os::unix::fs::symlink(&target, &marker).unwrap();

        assert!(!recently_checked(&marker, Duration::from_secs(60 * 60)));
    }

    /// # Contract
    ///
    /// A hardlinked update-check marker is not authoritative cache
    /// state. Only a marker owned by its cache path may suppress the
    /// network update probe.
    #[cfg(unix)]
    #[test]
    fn hardlinked_marker_is_not_recent() {
        let dir = tempfile::TempDir::new().unwrap();
        let target = dir.path().join("target-marker");
        let marker = dir.path().join(MARKER_FILENAME);
        std::fs::write(&target, b"recent").unwrap();
        std::fs::hard_link(&target, &marker).unwrap();

        let is_recent = recently_checked(&marker, Duration::from_secs(60 * 60));

        assert!(!is_recent);
    }

    /// # Contract
    ///
    /// Touching the update-check marker replaces a symlinked entry
    /// without overwriting the target.
    #[cfg(unix)]
    #[test]
    fn touch_marker_replaces_symlink_without_touching_target() {
        let dir = tempfile::TempDir::new().unwrap();
        let target = dir.path().join("target-marker");
        let marker = dir.path().join(MARKER_FILENAME);
        std::fs::write(&target, b"keep").unwrap();
        std::os::unix::fs::symlink(&target, &marker).unwrap();

        touch_marker(&marker).unwrap();

        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
        assert!(!std::fs::symlink_metadata(&marker)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(recently_checked(&marker, Duration::from_secs(60 * 60)));
    }

    /// Contract: update-check release tags are display-safe release
    /// identifiers, not arbitrary redirect suffixes.
    #[test]
    fn validate_release_tag_rejects_display_unsafe_shapes() {
        assert!(validate_release_tag("v1.2.3").is_ok());
        for bad in ["", "1.2.3", "v1.2.3/../../x", "v1.2.3\nx", "v1.2.3?x=1"] {
            assert!(
                validate_release_tag(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    /// Contract: update-check NOVA values are commit SHA strings before
    /// they are compared or rendered.
    #[test]
    fn validate_nova_sha_rejects_display_unsafe_shapes() {
        assert!(validate_nova_sha("9249cf49dce2b30550bc23d00a36ec64d42932d0").is_ok());
        for bad in [
            "",
            "deadbeef",
            "9249cf49dce2b30550bc23d00a36ec64d42932d0/../../x",
            "9249cf49dce2b30550bc23d00a36ec64d42932dg",
            "9249cf49dce2b30550bc23d00a36ec64d42932d0\nx",
        ] {
            assert!(validate_nova_sha(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    /// Contract: SHA shortening is character-boundary safe.
    #[test]
    fn short_sha_is_utf8_boundary_safe() {
        assert_eq!(short_sha("abcdefghi"), "abcdefg");
        assert_eq!(short_sha("åååååååå"), "ååååååå");
    }

    /// Contract: GitHub update-check JSON bodies are bounded before
    /// parsing.
    #[test]
    fn read_string_bounded_rejects_oversized_body() {
        let ok = read_string_bounded(std::io::Cursor::new(b"abc".to_vec()), 3).unwrap();
        assert_eq!(ok, "abc");

        let err = read_string_bounded(std::io::Cursor::new(b"abcd".to_vec()), 3)
            .expect_err("over-cap update body must be rejected");

        assert!(format!("{err:#}").contains("exceeded 3 bytes"));
    }
}
