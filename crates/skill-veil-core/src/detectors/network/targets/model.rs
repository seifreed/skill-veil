#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NetworkTarget {
    MetadataService,
    Loopback,
    Localhost,
    BindAll,
    Rfc1918_10,
    Rfc1918_192,
    Rfc1918_172,
    InternalDomain,
    LocalDomain,
}

impl NetworkTarget {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::MetadataService => "169.254.169.254",
            Self::Loopback => "127.0.0.1",
            Self::Localhost => "localhost",
            Self::BindAll => "0.0.0.0",
            Self::Rfc1918_10 => "rfc1918:10/8",
            Self::Rfc1918_192 => "rfc1918:192.168/16",
            Self::Rfc1918_172 => "rfc1918:172.16/12",
            Self::InternalDomain => ".internal",
            Self::LocalDomain => ".local",
        }
    }

    pub(crate) fn rule_id(self) -> &'static str {
        if matches!(self, Self::MetadataService) {
            "METADATA_SERVICE_ACCESS"
        } else {
            "INTERNAL_NETWORK_ACCESS"
        }
    }

    pub(crate) fn threat_category(self) -> crate::findings::ThreatCategory {
        if matches!(self, Self::MetadataService) {
            crate::findings::ThreatCategory::CredentialExposure
        } else {
            crate::findings::ThreatCategory::ToolAbuse
        }
    }

    pub(crate) fn action(self) -> crate::findings::RecommendedAction {
        if matches!(self, Self::MetadataService) {
            crate::findings::RecommendedAction::RequireApproval
        } else {
            crate::findings::RecommendedAction::Log
        }
    }

    pub(crate) fn signal_class(self) -> crate::findings::SignalClass {
        if matches!(self, Self::MetadataService) {
            crate::findings::SignalClass::SuspiciousPackageBehavior
        } else {
            crate::findings::SignalClass::ReviewSignal
        }
    }

    pub(crate) fn reason(self) -> &'static str {
        if matches!(self, Self::MetadataService) {
            "Artifact references a metadata service target commonly used for credential discovery"
        } else {
            "Artifact references internal or loopback network targets"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::NetworkTarget;
    use crate::findings::{RecommendedAction, SignalClass, ThreatCategory};

    #[test]
    fn metadata_service_target_maps_to_stronger_policy_defaults() {
        assert_eq!(
            NetworkTarget::MetadataService.rule_id(),
            "METADATA_SERVICE_ACCESS"
        );
        assert_eq!(
            NetworkTarget::MetadataService.threat_category(),
            ThreatCategory::CredentialExposure
        );
        assert_eq!(
            NetworkTarget::MetadataService.action(),
            RecommendedAction::RequireApproval
        );
        assert_eq!(
            NetworkTarget::MetadataService.signal_class(),
            SignalClass::SuspiciousPackageBehavior
        );
    }

    #[test]
    fn localhost_like_targets_keep_review_semantics() {
        assert_eq!(NetworkTarget::Localhost.label(), "localhost");
        assert_eq!(NetworkTarget::BindAll.action(), RecommendedAction::Log);
        assert_eq!(
            NetworkTarget::LocalDomain.signal_class(),
            SignalClass::ReviewSignal
        );
    }
}
