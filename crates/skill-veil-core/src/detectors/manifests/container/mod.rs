//! Container manifest detectors split into single-responsibility submodules.
//!
//! - [`dockerfile`] — `Dockerfile` finding emission, capability inference,
//!   and artifact relations.
//! - [`compose`] — `docker-compose.yml` analyses (per-service findings,
//!   capabilities, relations).
//! - [`volumes`] — pure classifiers shared by `compose`: which volume
//!   shapes count as sensitive host mounts, which `env_file` shapes carry
//!   real paths, and how to render an `env_file` value for audit output.

pub(crate) mod compose;
pub(crate) mod dockerfile;
pub(crate) mod volumes;

fn image_uses_mutable_latest(image: &str) -> bool {
    let image = image.trim();
    if image.is_empty() {
        return false;
    }
    let (reference, digest) = image
        .split_once('@')
        .map_or((image, None), |(reference, digest)| {
            (reference, Some(digest.trim()))
        });
    if digest.is_some_and(|value| !value.is_empty()) {
        return false;
    }
    if reference.eq_ignore_ascii_case("scratch") {
        return false;
    }
    let Some(last_colon) = reference.rfind(':') else {
        return true;
    };
    let last_slash = reference.rfind('/');
    if last_slash.is_some_and(|slash| last_colon < slash) {
        return true;
    }
    reference[last_colon + 1..].eq_ignore_ascii_case("latest")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: Docker image references without a tag resolve to the
    /// mutable `latest` tag unless they are the special `scratch` base.
    #[test]
    fn image_uses_mutable_latest_accepts_implicit_latest() {
        assert!(image_uses_mutable_latest("alpine"));
        assert!(image_uses_mutable_latest("library/alpine"));
        assert!(image_uses_mutable_latest("localhost:5000/alpine"));
        assert!(!image_uses_mutable_latest("scratch"));
    }

    /// Contract: explicit `latest` is mutable, but tags that merely start
    /// with that text and digest-pinned images are not.
    #[test]
    fn image_uses_mutable_latest_distinguishes_tags_and_digests() {
        assert!(image_uses_mutable_latest("alpine:latest"));
        assert!(image_uses_mutable_latest(
            "registry.local:5000/team/app:latest"
        ));
        assert!(!image_uses_mutable_latest("alpine:3.19"));
        assert!(!image_uses_mutable_latest("alpine:latest-rc"));
        assert!(!image_uses_mutable_latest(
            "alpine@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
        assert!(!image_uses_mutable_latest(
            "alpine:latest@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
    }
}
