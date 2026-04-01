use crate::findings::{BlastRadiusSummary, SkillCapability};

pub(crate) fn derive_top_reasons(
    top_risk_drivers: &[crate::findings::RiskFactor],
    effective_capabilities: &[SkillCapability],
    blast_radius_summary: &BlastRadiusSummary,
) -> Vec<String> {
    let mut reasons = Vec::new();

    for factor in top_risk_drivers {
        if let Some(reason) = map_factor_to_reason(&factor.factor) {
            if !reasons.iter().any(|item| item == reason) {
                reasons.push(reason.to_string());
            }
        }
    }

    if reasons.is_empty() {
        if effective_capabilities.contains(&SkillCapability::ShellExec) {
            reasons.push("shell execution".to_string());
        }
        if effective_capabilities.contains(&SkillCapability::NetworkHttp)
            || effective_capabilities.contains(&SkillCapability::NetworkWebsocket)
            || effective_capabilities.contains(&SkillCapability::NetworkInternal)
        {
            reasons.push("network calls".to_string());
        }
        if effective_capabilities.contains(&SkillCapability::SecretsAccess) {
            reasons.push("secret access".to_string());
        }
    }

    for factor in &blast_radius_summary.factors {
        let normalized = factor.to_ascii_lowercase();
        let reason = if normalized.contains("network") {
            Some("network calls")
        } else if normalized.contains("secret") {
            Some("secret access")
        } else if normalized.contains("process") || normalized.contains("shell") {
            Some("shell execution")
        } else {
            None
        };
        if let Some(reason) = reason {
            if !reasons.iter().any(|item| item == reason) {
                reasons.push(reason.to_string());
            }
        }
    }

    reasons.truncate(3);
    reasons
}

fn map_factor_to_reason(factor: &str) -> Option<&'static str> {
    if factor.contains("composite:secret_exfiltration") {
        Some("secret exfiltration chain")
    } else if factor.contains("composite:shell_download_exec") {
        Some("download and execute chain")
    } else if factor.contains("composite:browser_write_chain") {
        Some("browser plus write chain")
    } else if factor.contains("composite:browser_session_exfiltration") {
        Some("browser session exfiltration chain")
    } else if factor.contains("composite:remote_mcp_no_auth_exec") {
        Some("unauthenticated remote MCP execution")
    } else if factor.contains("composite:remote_mcp_no_auth") {
        Some("remote MCP without auth")
    } else if factor.contains("composite:workflow_exec_persistence") {
        Some("workflow fetch-exec-persist chain")
    } else if factor.contains("provenance:untrusted") {
        Some("untrusted provenance")
    } else if factor.contains("provenance:review") {
        Some("external provenance")
    } else if factor.contains("shell") || factor.contains("exec") || factor.contains("process") {
        Some("shell execution")
    } else if factor.contains("network") {
        Some("network calls")
    } else if factor.contains("secret") || factor.contains("credential") {
        Some("secret access")
    } else if factor.contains("browser") {
        Some("browser automation")
    } else if factor.contains("oauth") || factor.contains("identity") {
        Some("oauth/identity access")
    } else if factor.contains("persistence") {
        Some("persistence")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_reasons_dedup_and_preserve_driver_order() {
        let reasons = derive_top_reasons(
            &[
                crate::findings::RiskFactor {
                    factor: "composite:remote_mcp_no_auth_exec".to_string(),
                    contribution: 19,
                    rationale: "critical".to_string(),
                },
                crate::findings::RiskFactor {
                    factor: "composite:remote_mcp_no_auth".to_string(),
                    contribution: 16,
                    rationale: "critical".to_string(),
                },
                crate::findings::RiskFactor {
                    factor: "provenance:review".to_string(),
                    contribution: 3,
                    rationale: "review".to_string(),
                },
            ],
            &[],
            &BlastRadiusSummary::default(),
        );
        assert_eq!(
            reasons,
            vec![
                "unauthenticated remote MCP execution",
                "remote MCP without auth",
                "external provenance",
            ]
        );
    }
}
