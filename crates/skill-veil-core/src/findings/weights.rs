// Severity weights use an intentionally non-linear scale so that a single Critical
// finding (90) outweighs nine Low findings (10 each), and a single High finding at
// 0.9 confidence (~54) already crosses the Block threshold on its own.
/// Weight applied to Low severity findings in risk score calculation.
pub const SEVERITY_WEIGHT_LOW: u32 = 10;
/// Weight applied to Medium severity findings in risk score calculation.
pub const SEVERITY_WEIGHT_MEDIUM: u32 = 30;
/// Weight applied to High severity findings in risk score calculation.
pub const SEVERITY_WEIGHT_HIGH: u32 = 60;
/// Weight applied to Critical severity findings in risk score calculation.
pub const SEVERITY_WEIGHT_CRITICAL: u32 = 90;

// Block at 50 so a single High finding at typical confidence (~54) hits it immediately.
// Approval at 20 so a single Medium finding at 0.7 confidence (~21) reliably triggers review.
/// Risk score threshold above which action is Block.
pub const RISK_THRESHOLD_BLOCK: u32 = 50;
/// Risk score threshold above which action is RequireApproval.
pub const RISK_THRESHOLD_APPROVAL: u32 = 20;
/// Maximum risk score. Used as the upper bound when normalizing weighted
/// scores and as the fail-safe value when score normalization encounters
/// non-finite arithmetic (a Block-level ceiling is the right default for a
/// security scanner).
pub const MAX_RISK_SCORE: u32 = 100;

// Evidence weights reflect signal reliability: IOC is nearly deterministic (10),
// behavioral patterns are very reliable (8), intent requires interpretation (4),
// and context alone is the weakest signal (3).
/// Bonus applied to IOC-backed findings in explainable risk scoring.
pub const EVIDENCE_WEIGHT_IOC: u32 = 10;
/// Bonus applied to behavioral findings in explainable risk scoring.
pub const EVIDENCE_WEIGHT_BEHAVIOR: u32 = 8;
/// Bonus applied to intent findings in explainable risk scoring.
pub const EVIDENCE_WEIGHT_INTENT: u32 = 4;
/// Bonus applied to context findings in explainable risk scoring.
pub const EVIDENCE_WEIGHT_CONTEXT: u32 = 3;

// Capability weights reflect the direct blast radius of each capability.
// PRIVILEGED_RUNTIME (18) and HOST_FILESYSTEM_ACCESS (16) are highest because they
// give full system/container access. SECRET_ACCESS and IDENTITY_ACCESS (14) are
// high because they expose credentials directly. NETWORK_ACCESS (6) is low because
// it is ubiquitous in legitimate packages and alone carries little signal.
/// Bonus applied when an artifact exposes install-time execution capability.
pub const CAPABILITY_WEIGHT_INSTALL_EXECUTION: u32 = 8;
/// Bonus applied when an artifact exposes network access.
pub const CAPABILITY_WEIGHT_NETWORK_ACCESS: u32 = 6;
/// Bonus applied when an artifact exposes local binaries.
pub const CAPABILITY_WEIGHT_EXPOSES_BINARY: u32 = 4;
/// Bonus applied when an artifact requests privileged runtime (e.g., `--privileged` Docker flag).
pub const CAPABILITY_WEIGHT_PRIVILEGED_RUNTIME: u32 = 18;
/// Bonus applied when an artifact can access the host filesystem (e.g., volume mounts).
pub const CAPABILITY_WEIGHT_HOST_FILESYSTEM_ACCESS: u32 = 16;
/// Bonus applied when an artifact can execute child processes.
pub const CAPABILITY_WEIGHT_PROCESS_EXECUTION: u32 = 10;
/// Bonus applied when an artifact can read or expose secrets.
pub const CAPABILITY_WEIGHT_SECRET_ACCESS: u32 = 14;
/// Bonus applied when an artifact establishes persistence.
pub const CAPABILITY_WEIGHT_PERSISTENCE_SURFACE: u32 = 12;
/// Bonus applied when an artifact can write to the filesystem.
pub const CAPABILITY_WEIGHT_FILESYSTEM_WRITE: u32 = 9;
/// Bonus applied when an artifact declares browser automation access.
pub const CAPABILITY_WEIGHT_BROWSER_ACCESS: u32 = 8;
/// Bonus applied when an artifact can access identity or OAuth material.
pub const CAPABILITY_WEIGHT_IDENTITY_ACCESS: u32 = 14;
/// Bonus applied when an artifact exposes inbound network/webhook surface.
pub const CAPABILITY_WEIGHT_INBOUND_SURFACE: u32 = 10;

// Combo weights are bonuses on top of individual capability weights.
// PRIVILEGED_HOST (25) is the highest combo because privileged + host filesystem
// is a complete container escape. INSTALL_NETWORK (12) captures the classic dropper
// pattern (download + execute at install time).
/// Bonus applied to the high-risk privileged + host filesystem combination — complete container escape.
pub const CAPABILITY_COMBO_WEIGHT_PRIVILEGED_HOST: u32 = 25;
/// Bonus applied to install-time execution combined with network access — classic dropper pattern.
pub const CAPABILITY_COMBO_WEIGHT_INSTALL_NETWORK: u32 = 12;
/// Bonus applied to install-time execution that also exposes binaries.
pub const CAPABILITY_COMBO_WEIGHT_INSTALL_BINARY: u32 = 8;
/// Bonus applied to secret access combined with network connectivity — exfiltration path.
pub const CAPABILITY_COMBO_WEIGHT_SECRET_NETWORK: u32 = 10;
/// Bonus applied to persistence combined with network connectivity.
pub const CAPABILITY_COMBO_WEIGHT_PERSISTENCE_NETWORK: u32 = 8;
/// Bonus applied to browser automation combined with identity/OAuth access — session hijack path.
pub const CAPABILITY_COMBO_WEIGHT_BROWSER_IDENTITY: u32 = 10;

// Signal weights are dampening factors applied before capability bonuses.
// HYGIENE (0.35) is heavily dampened so hygiene-only packages never reach the
// Block threshold. MALICIOUS (1.0) carries full weight. SUSPICIOUS (0.75) and
// REVIEW (0.5) sit between, reflecting increasing uncertainty.
/// Dampening factor for hygiene-only signals — prevents hygiene packages from reaching Block.
pub const SIGNAL_WEIGHT_HYGIENE: f32 = 0.35;
/// Dampening factor for suspicious but not clearly malicious signals.
pub const SIGNAL_WEIGHT_SUSPICIOUS: f32 = 0.75;
/// Full weight for clearly malicious behavior signals.
pub const SIGNAL_WEIGHT_MALICIOUS: f32 = 1.0;
/// Dampening factor for generic review signals.
pub const SIGNAL_WEIGHT_REVIEW: f32 = 0.5;

// Confidence calibration blend coefficients. The calibrated confidence is
// `raw * RAW_WEIGHT + baseline * BASELINE_WEIGHT`, then clamped to
// [`CONFIDENCE_FLOOR`, `CONFIDENCE_CEILING`]. Weights MUST sum to 1.0; the
// 70/30 split keeps the rule's authored confidence dominant while letting the
// per-axis baseline pull weak signals up and saturate near-deterministic
// evidence at the ceiling. Floor/ceiling avoid 0.0/1.0 since downstream
// log-odds math relies on a strictly positive, sub-unit value.
/// Weight applied to the rule-authored raw confidence in the blend.
pub const CONFIDENCE_RAW_WEIGHT: f32 = 0.7;
/// Weight applied to the per-axis baseline (evidence + category mean) in the blend.
pub const CONFIDENCE_BASELINE_WEIGHT: f32 = 0.3;
/// Lower clamp for calibrated confidence; keeps log-odds math finite.
pub const CONFIDENCE_FLOOR: f32 = 0.1;
/// Upper clamp for calibrated confidence; keeps log-odds math finite.
pub const CONFIDENCE_CEILING: f32 = 0.99;

// Confidence calibration baselines for evidence kinds
/// Baseline confidence for IOC-backed findings.
pub const EVIDENCE_BASELINE_IOC: f32 = 0.98;
/// Baseline confidence for behavioral findings.
pub const EVIDENCE_BASELINE_BEHAVIOR: f32 = 0.92;
/// Baseline confidence for intent-based findings.
pub const EVIDENCE_BASELINE_INTENT: f32 = 0.84;
/// Baseline confidence for context-based findings.
pub const EVIDENCE_BASELINE_CONTEXT: f32 = 0.78;

// Confidence calibration baselines for threat categories
/// Baseline for high-risk categories (RemoteExec, CredentialExposure, DataExfiltration).
pub const CATEGORY_BASELINE_HIGH_RISK: f32 = 0.94;
/// Baseline for supply-chain and privilege categories.
pub const CATEGORY_BASELINE_SUPPLY_CHAIN: f32 = 0.90;
/// Baseline for tool abuse and prompt tampering categories.
pub const CATEGORY_BASELINE_TOOL_ABUSE: f32 = 0.86;
/// Baseline for autonomy and scope creep categories.
pub const CATEGORY_BASELINE_AUTONOMY: f32 = 0.84;
/// Baseline for social manipulation categories.
pub const CATEGORY_BASELINE_SOCIAL: f32 = 0.80;
/// Baseline for obfuscation category.
pub const CATEGORY_BASELINE_OBFUSCATION: f32 = 0.82;
/// Baseline for generic category.
pub const CATEGORY_BASELINE_GENERIC: f32 = 0.76;
