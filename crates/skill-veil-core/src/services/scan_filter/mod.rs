//! Apply post-scan filters to findings: minimum severity and rule
//! include/exclude lists from `ScanOptions`.

use crate::findings::{Finding, RecommendedAction, Severity};
use crate::policy::{
    apply_baseline, apply_policy_overrides_with_audit, apply_waivers, count_baseline_matches,
    finding_fingerprint, AppliedPolicyOverride, BaselineFile, PolicyFile, PolicyProfile,
    SuppressionSummary, WaiverFile,
};
use crate::scanner_types::{ScanOptions, ScanTargetMode};
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct FilterOutcome {
    pub findings: Vec<Finding>,
    pub suppression_summary: SuppressionSummary,
    pub applied_overrides: Vec<AppliedPolicyOverride>,
}

/// Service for filtering scan results
pub struct ScanFilterService {
    min_severity: Option<Severity>,
    fail_on: Option<Severity>,
    include_rules: BTreeSet<String>,
    exclude_rules: BTreeSet<String>,
    profile: Option<PolicyProfile>,
    target_mode: ScanTargetMode,
    baseline: Option<BaselineFile>,
    waivers: Option<WaiverFile>,
    policy: Option<PolicyFile>,
}

impl ScanFilterService {
    pub fn new(options: ScanOptions) -> Self {
        Self::with_policy_state(options, None, None, None)
    }

    pub fn with_policy_state(
        options: ScanOptions,
        baseline: Option<BaselineFile>,
        waivers: Option<WaiverFile>,
        policy: Option<PolicyFile>,
    ) -> Self {
        Self {
            min_severity: options.min_severity,
            fail_on: options.fail_on,
            include_rules: options.include_rules.into_iter().collect(),
            exclude_rules: options.exclude_rules.into_iter().collect(),
            profile: options.profile,
            target_mode: options.target_mode,
            baseline,
            waivers,
            policy,
        }
    }

    /// Filter findings based on configured options
    ///
    /// Applies the following filters in order:
    /// 1. Minimum severity filter - excludes findings below threshold
    /// 2. Include rules filter - only includes specified rule IDs (if any)
    /// 3. Exclude rules filter - excludes specified rule IDs
    ///
    /// # Arguments
    /// * `findings` - The findings to filter
    ///
    /// # Returns
    /// Filtered findings matching the configured criteria
    pub fn filter_findings(&self, findings: Vec<Finding>) -> Vec<Finding> {
        self.filter_with_summary(findings).findings
    }

    pub fn filter_with_summary(&self, findings: Vec<Finding>) -> FilterOutcome {
        // Apply policy overrides BEFORE severity filtering so that Block
        // overrides can escalate findings above the minimum severity threshold.
        // Pre-fix the severity filter ran first, silently discarding
        // findings whose native severity was below `--min-severity` before
        // overrides had a chance to promote their action to Block — defeating
        // the operator intent encoded in `should_fail`'s Block-action bypass.
        let (findings, applied_overrides) = self.apply_overrides_stage(findings);
        // Collect fingerprints of findings whose action was escalated TO Block
        // by a policy override. These findings must survive the severity filter
        // regardless of their native severity — the operator explicitly chose
        // "halt on this rule" and that intent must not be silently discarded.
        let block_overridden_fingerprints: BTreeSet<String> = applied_overrides
            .iter()
            .filter(|ov| ov.effective_action == RecommendedAction::Block)
            .map(|ov| ov.finding_fingerprint.clone())
            .collect();
        let findings =
            self.apply_severity_filter_with_overrides(findings, &block_overridden_fingerprints);
        let (findings, waiver_suppressed) = self.apply_waivers_stage(findings);
        let (findings, baseline_suppressed) = self.apply_baseline_stage(findings);

        FilterOutcome {
            suppression_summary: SuppressionSummary {
                baseline_suppressed,
                waiver_suppressed,
                inline_suppressed: 0,
                active_findings: findings
                    .iter()
                    .filter(|f| f.recommended_action != RecommendedAction::Log)
                    .count(),
            },
            applied_overrides,
            findings,
        }
    }

    fn apply_severity_filter_with_overrides(
        &self,
        findings: Vec<Finding>,
        block_overridden_fingerprints: &BTreeSet<String>,
    ) -> Vec<Finding> {
        findings
            .into_iter()
            .filter(|f| {
                // A finding escalated to Block by a policy override always
                // survives the severity filter. The operator's explicit "halt
                // on this rule" intent must override any severity gate.
                if block_overridden_fingerprints.contains(&finding_fingerprint(f)) {
                    return true;
                }
                self.should_include_by_severity_and_rules(f)
            })
            .collect()
    }

    fn apply_waivers_stage(&self, findings: Vec<Finding>) -> (Vec<Finding>, usize) {
        let pre_count = findings.len();
        let findings = apply_waivers(findings, self.waivers.as_ref());
        let suppressed = pre_count.saturating_sub(findings.len());
        (findings, suppressed)
    }

    fn apply_baseline_stage(&self, findings: Vec<Finding>) -> (Vec<Finding>, usize) {
        let suppressed = count_baseline_matches(&findings, self.baseline.as_ref());
        let findings = apply_baseline(findings, self.baseline.as_ref());
        (findings, suppressed)
    }

    fn apply_overrides_stage(
        &self,
        findings: Vec<Finding>,
    ) -> (Vec<Finding>, Vec<AppliedPolicyOverride>) {
        apply_policy_overrides_with_audit(findings, self.policy.as_ref())
    }

    /// Determine if a finding should be included based on severity and rule filters.
    ///
    /// This does NOT consider policy-override-escalated Block actions — those
    /// are handled separately in `apply_severity_filter_with_overrides`.
    fn should_include_by_severity_and_rules(&self, finding: &Finding) -> bool {
        // Filter by minimum severity
        if let Some(min_sev) = self.min_severity {
            if finding.severity < min_sev {
                return false;
            }
        }

        // Filter by include rules (if specified, only those rules are included)
        if !self.include_rules.is_empty() && !self.include_rules.contains(&finding.rule_id) {
            return false;
        }

        // Filter by exclude rules
        if self.exclude_rules.contains(&finding.rule_id) {
            return false;
        }

        true
    }

    /// Check if any findings should trigger a failure based on fail_on threshold.
    ///
    /// # Arguments
    /// * `findings` - The findings to check
    ///
    /// # Returns
    ///
    /// `false` when no `fail_on` threshold is configured (no profile, no
    /// `--fail-on` flag).
    ///
    /// Otherwise `true` when any finding either:
    /// - meets or exceeds the `fail_on` severity threshold (and is not a
    ///   `Log`-action finding), OR
    /// - carries a [`RecommendedAction::Block`] action regardless of
    ///   severity.
    ///
    /// The second clause closes a real CI-bypass: a `High`-severity finding
    /// whose action was *escalated to `Block`* by a policy override under a
    /// `Personal` profile (`fail_on = Critical`) used to silently pass
    /// because `High < Critical`. `Block` encodes operator intent — "halt
    /// on this rule" — that the severity gate alone cannot represent.
    /// Confining the new clause to the `fail_on.is_some()` branch preserves
    /// the historical "no threshold → never fail" contract for callers that
    /// deliberately scan with `fail_on = None` (informational scans, IDE
    /// integrations).
    pub fn should_fail(&self, findings: &[Finding]) -> bool {
        let Some(sev) = self.fail_on() else {
            return false;
        };
        findings.iter().any(|f| {
            f.recommended_action == RecommendedAction::Block
                || (f.severity >= sev && f.recommended_action != RecommendedAction::Log)
        })
    }

    /// Get the minimum severity threshold
    pub fn min_severity(&self) -> Option<Severity> {
        self.min_severity
    }

    /// Get the fail-on severity threshold
    pub fn fail_on(&self) -> Option<Severity> {
        self.fail_on.or_else(|| {
            self.profile.and_then(|profile| {
                self.policy.as_ref().map_or_else(
                    || profile.default_fail_on(),
                    |policy| policy.resolve_fail_on(profile),
                )
            })
        })
    }

    /// Get the target mode used for scanning.
    pub fn target_mode(&self) -> ScanTargetMode {
        self.target_mode
    }

    pub fn profile(&self) -> Option<PolicyProfile> {
        self.profile
    }

    pub fn policy(&self) -> Option<&PolicyFile> {
        self.policy.as_ref()
    }
}

#[cfg(test)]
mod tests;
