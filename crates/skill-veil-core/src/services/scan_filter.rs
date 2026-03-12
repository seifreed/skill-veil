//! Scan filtering service - applies filters to findings
//!
//! This service is responsible for filtering scan results based on
//! configured options like minimum severity and rule inclusion/exclusion.

use crate::findings::{Finding, Severity};
use crate::policy::{
    apply_baseline, apply_policy_overrides_with_audit, apply_waivers, AppliedPolicyOverride,
    BaselineFile, PolicyFile, PolicyProfile, SuppressionSummary, WaiverFile,
};
use crate::scanner::{ScanOptions, ScanTargetMode};

#[derive(Debug, Clone)]
pub struct FilterOutcome {
    pub findings: Vec<Finding>,
    pub suppression_summary: SuppressionSummary,
    pub applied_overrides: Vec<AppliedPolicyOverride>,
}

/// Service for filtering scan results
pub struct ScanFilterService {
    options: ScanOptions,
    baseline: Option<BaselineFile>,
    waivers: Option<WaiverFile>,
    policy: Option<PolicyFile>,
}

impl ScanFilterService {
    /// Create a new scan filter service
    ///
    /// # Arguments
    /// * `options` - The scan options containing filter configuration
    pub fn new(options: ScanOptions) -> Self {
        Self {
            options,
            baseline: None,
            waivers: None,
            policy: None,
        }
    }

    pub fn with_policy_state(
        options: ScanOptions,
        baseline: Option<BaselineFile>,
        waivers: Option<WaiverFile>,
        policy: Option<PolicyFile>,
    ) -> Self {
        Self {
            options,
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
        let findings = findings
            .into_iter()
            .filter(|f| self.should_include(f))
            .collect::<Vec<_>>();
        let pre_waiver_count = findings.len();
        let findings = apply_waivers(findings, self.waivers.as_ref());
        let waiver_suppressed = pre_waiver_count.saturating_sub(findings.len());
        let pre_baseline_count = findings.len();
        let findings = apply_baseline(findings, self.baseline.as_ref());
        let baseline_suppressed = pre_baseline_count.saturating_sub(findings.len());
        let (findings, applied_overrides) =
            apply_policy_overrides_with_audit(findings, self.policy.as_ref());

        FilterOutcome {
            suppression_summary: SuppressionSummary {
                baseline_suppressed,
                waiver_suppressed,
                active_findings: findings.len(),
            },
            applied_overrides,
            findings,
        }
    }

    /// Determine if a finding should be included based on filter options
    fn should_include(&self, finding: &Finding) -> bool {
        // Filter by minimum severity
        if let Some(min_sev) = &self.options.min_severity {
            if finding.severity < *min_sev {
                return false;
            }
        }

        // Filter by include rules (if specified, only those rules are included)
        if !self.options.include_rules.is_empty()
            && !self.options.include_rules.contains(&finding.rule_id)
        {
            return false;
        }

        // Filter by exclude rules
        if self.options.exclude_rules.contains(&finding.rule_id) {
            return false;
        }

        true
    }

    /// Check if any findings should trigger a failure based on fail_on threshold
    ///
    /// # Arguments
    /// * `findings` - The findings to check
    ///
    /// # Returns
    /// `true` if any finding meets or exceeds the fail_on severity threshold
    pub fn should_fail(&self, findings: &[Finding]) -> bool {
        self.fail_on()
            .map(|sev| findings.iter().any(|f| f.severity >= sev))
            .unwrap_or(false)
    }

    /// Get the minimum severity threshold
    pub fn min_severity(&self) -> Option<Severity> {
        self.options.min_severity
    }

    /// Get the fail-on severity threshold
    pub fn fail_on(&self) -> Option<Severity> {
        self.options.fail_on.or_else(|| {
            self.options.profile.and_then(|profile| {
                self.policy.as_ref().map_or_else(
                    || profile.default_fail_on(),
                    |policy| policy.resolve_fail_on(profile),
                )
            })
        })
    }

    /// Get the target mode used for scanning.
    pub fn target_mode(&self) -> ScanTargetMode {
        self.options.target_mode
    }

    pub fn profile(&self) -> Option<PolicyProfile> {
        self.options.profile
    }

    pub fn policy(&self) -> Option<&PolicyFile> {
        self.policy.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{MatchTarget, ThreatCategory};
    use crate::policy::{BaselineEntry, BaselineFile, PolicyProfile, WaiverEntry, WaiverFile};

    fn create_finding(rule_id: &str, severity: Severity) -> Finding {
        Finding::builder(rule_id, ThreatCategory::Generic)
            .severity(severity)
            .confidence(0.9)
            .matched_on(MatchTarget::Document)
            .match_value("test")
            .reason("Test finding")
            .build()
    }

    #[test]
    fn test_filter_by_min_severity() {
        let options = ScanOptions {
            min_severity: Some(Severity::High),
            ..Default::default()
        };
        let filter = ScanFilterService::new(options);

        let findings = vec![
            create_finding("R1", Severity::Low),
            create_finding("R2", Severity::Medium),
            create_finding("R3", Severity::High),
            create_finding("R4", Severity::Critical),
        ];

        let filtered = filter.filter_findings(findings);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|f| f.severity >= Severity::High));
    }

    #[test]
    fn test_filter_by_include_rules() {
        let options = ScanOptions {
            include_rules: vec!["R1".to_string(), "R3".to_string()],
            ..Default::default()
        };
        let filter = ScanFilterService::new(options);

        let findings = vec![
            create_finding("R1", Severity::High),
            create_finding("R2", Severity::High),
            create_finding("R3", Severity::High),
            create_finding("R4", Severity::High),
        ];

        let filtered = filter.filter_findings(findings);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().any(|f| f.rule_id == "R1"));
        assert!(filtered.iter().any(|f| f.rule_id == "R3"));
    }

    #[test]
    fn test_filter_by_exclude_rules() {
        let options = ScanOptions {
            exclude_rules: vec!["R2".to_string()],
            ..Default::default()
        };
        let filter = ScanFilterService::new(options);

        let findings = vec![
            create_finding("R1", Severity::High),
            create_finding("R2", Severity::High),
            create_finding("R3", Severity::High),
        ];

        let filtered = filter.filter_findings(findings);
        assert_eq!(filtered.len(), 2);
        assert!(!filtered.iter().any(|f| f.rule_id == "R2"));
    }

    #[test]
    fn test_combined_filters() {
        let options = ScanOptions {
            min_severity: Some(Severity::Medium),
            exclude_rules: vec!["R2".to_string()],
            ..Default::default()
        };
        let filter = ScanFilterService::new(options);

        let findings = vec![
            create_finding("R1", Severity::Low),
            create_finding("R2", Severity::High),
            create_finding("R3", Severity::Medium),
            create_finding("R4", Severity::Critical),
        ];

        let filtered = filter.filter_findings(findings);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().any(|f| f.rule_id == "R3"));
        assert!(filtered.iter().any(|f| f.rule_id == "R4"));
    }

    #[test]
    fn test_should_fail() {
        let options = ScanOptions {
            fail_on: Some(Severity::High),
            ..Default::default()
        };
        let filter = ScanFilterService::new(options);

        let low_findings = vec![
            create_finding("R1", Severity::Low),
            create_finding("R2", Severity::Medium),
        ];
        assert!(!filter.should_fail(&low_findings));

        let high_findings = vec![
            create_finding("R1", Severity::Low),
            create_finding("R2", Severity::High),
        ];
        assert!(filter.should_fail(&high_findings));
    }

    #[test]
    fn test_no_fail_on_threshold() {
        let options = ScanOptions::default();
        let filter = ScanFilterService::new(options);

        let findings = vec![create_finding("R1", Severity::Critical)];
        assert!(!filter.should_fail(&findings));
    }

    #[test]
    fn test_profile_supplies_default_fail_threshold() {
        let options = ScanOptions {
            profile: Some(PolicyProfile::Team),
            ..Default::default()
        };
        let filter = ScanFilterService::new(options);
        let findings = vec![create_finding("R1", Severity::High)];
        assert!(filter.should_fail(&findings));
    }

    #[test]
    fn test_filter_with_summary_counts_waivers_and_baseline() {
        let finding = create_finding("R1", Severity::High).with_artifact(
            crate::findings::ArtifactKind::ReferencedArtifact,
            "scripts/install.sh",
        );
        let baseline = BaselineFile {
            schema_version: crate::policy::POLICY_SCHEMA_VERSION.to_string(),
            entries: vec![BaselineEntry {
                fingerprint: crate::policy::finding_fingerprint(&finding),
                rule_id: finding.rule_id.clone(),
                artifact_path: finding.artifact_path.clone(),
                reason: finding.reason.clone(),
            }],
        };
        let waivers = WaiverFile {
            schema_version: crate::policy::POLICY_SCHEMA_VERSION.to_string(),
            waivers: vec![WaiverEntry {
                rule_id: Some("R2".to_string()),
                artifact_path: Some("other.sh".to_string()),
                context: None,
                reason: "accepted".to_string(),
                expires_at: None,
            }],
        };
        let filter = ScanFilterService::with_policy_state(
            ScanOptions::default(),
            Some(baseline),
            Some(waivers),
            None,
        );

        let outcome = filter.filter_with_summary(vec![finding]);
        assert_eq!(outcome.findings.len(), 0);
        assert_eq!(outcome.suppression_summary.baseline_suppressed, 1);
        assert_eq!(outcome.suppression_summary.waiver_suppressed, 0);
        assert_eq!(outcome.suppression_summary.active_findings, 0);
    }
}
