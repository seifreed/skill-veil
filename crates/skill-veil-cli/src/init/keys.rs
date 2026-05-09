//! Embedded Ed25519 public keys used to verify rule-pack release manifests.
//!
//! Adding a new key here is a security-sensitive operation: the binary
//! will accept any release signed by ANY key in [`TRUSTED_KEYS`]. Only
//! add keys whose private counterparts are controlled by maintainers
//! authorised to cut a `skill-veil-rules` release. Rotation procedure
//! is documented in `keys/README.md` of the `skill-veil-rules` repo.
//!
//! Each entry is a 32-byte raw Ed25519 public key (the format produced
//! by `tail -c 32` over the SubjectPublicKeyInfo DER). Hex form is
//! preferred over base64 for diff-readability and grep-ability.

use ed25519_dalek::VerifyingKey;

/// One entry per trusted maintainer keypair. The `id` is purely for
/// human/log diagnostics — the verification path tries every key in
/// order and reports which one accepted the signature, or that none
/// did.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TrustedKey {
    pub(crate) id: &'static str,
    pub(crate) bytes: [u8; 32],
}

/// 2026 maintainer key. Generated 2026-05-09 with
/// `openssl genpkey -algorithm ed25519`. Public counterpart published
/// in `skill-veil-rules/KEYS.md`.
const SKILL_VEIL_RULES_2026: TrustedKey = TrustedKey {
    id: "skill-veil-rules-2026",
    bytes: [
        0xac, 0x6c, 0xae, 0xa3, 0x9e, 0x56, 0x2c, 0x24, 0x50, 0x93, 0xde, 0xbc, 0xe0, 0xf4, 0x79,
        0x72, 0xd0, 0xd5, 0x15, 0xba, 0xdd, 0x59, 0xad, 0xdf, 0x8a, 0x92, 0x8c, 0x6c, 0xc6, 0x62,
        0x30, 0xea,
    ],
};

/// All keys the binary trusts to sign rule-pack releases. Order is
/// preferred-first; the verification path stops at the first match.
pub(crate) const TRUSTED_KEYS: &[TrustedKey] = &[SKILL_VEIL_RULES_2026];

/// Materialise every embedded key as a verified `VerifyingKey`.
/// Errors here would mean a programming mistake (a non-canonical
/// 32-byte point shipped in the binary), so we propagate the failure
/// to the caller as an opaque error rather than silently dropping the
/// key — a missing key is a security regression.
pub(crate) fn verifying_keys(
) -> Result<Vec<(&'static str, VerifyingKey)>, ed25519_dalek::SignatureError> {
    TRUSTED_KEYS
        .iter()
        .map(|k| VerifyingKey::from_bytes(&k.bytes).map(|vk| (k.id, vk)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: every embedded key must be a canonical Ed25519 point.
    /// A non-canonical key would silently be skipped by `verifying_keys`
    /// and give us a release that nothing in the binary trusts —
    /// shipping such a binary would brick `skill-veil init` for every
    /// user. Catch it at test time instead.
    #[test]
    fn every_trusted_key_is_canonical() {
        let keys = verifying_keys().expect("trusted keys must decode");
        assert_eq!(
            keys.len(),
            TRUSTED_KEYS.len(),
            "verifying_keys() must surface every trusted key id"
        );
        for ((id, _vk), trusted) in keys.iter().zip(TRUSTED_KEYS.iter()) {
            assert_eq!(*id, trusted.id);
        }
    }

    /// Pin the 2026 key so a typo in the byte literal surfaces here
    /// instead of at the first user's `skill-veil init`. The hex form
    /// is what `KEYS.md` ships and what `xxd -p` produces from
    /// `keys/skill-veil-rules-2026.ed25519.pub.raw`.
    #[test]
    fn skill_veil_rules_2026_key_matches_published_hex() {
        const EXPECTED: &str = "ac6caea39e562c245093debce0f47972d0d515badd59addf8a928c6cc66230ea";
        let actual = hex::encode(SKILL_VEIL_RULES_2026.bytes);
        assert_eq!(actual, EXPECTED);
    }
}
