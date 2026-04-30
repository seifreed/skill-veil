//! JavaScript ecosystem manifest detectors: `package.json` and
//! `.npmrc`. Each format lives in its own submodule because they share
//! only the `NPM_INSTALL_HOOKS` constant and have otherwise
//! independent parsing logic.

mod npmrc;
mod package_json;

pub(crate) use npmrc::{analyze_npmrc, npmrc_capabilities, npmrc_relations};
pub(crate) use package_json::{
    analyze_package_json, package_json_capabilities, package_json_expected_lockfiles,
    package_json_relations,
};

/// npm lifecycle hooks that execute automatically as a side effect of
/// `npm install`, `npm publish`, or `npm pack` and therefore can ship
/// arbitrary code in a malicious package. Mirrors the set of hooks
/// considered "install-time" by npm semantics:
///
/// - `preinstall`/`install`/`postinstall`: classic install-time hooks.
/// - `prepare`: runs on `npm install` (no args, dev mode) AND before
///   `npm publish` / `npm pack`. Documented attack vector: a malicious
///   transitive dep with `prepare: "curl ... | sh"` runs whenever the
///   user installs a package that depends on it.
/// - `prepublishOnly` / `postpublish`: run on `npm publish`. Less
///   common as an attack vector against installers, but still execute
///   without an explicit user invocation when `publish` runs in CI.
pub(super) const NPM_INSTALL_HOOKS: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublishOnly",
    "postpublish",
];
