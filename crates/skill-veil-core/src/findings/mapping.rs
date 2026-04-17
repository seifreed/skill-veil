use super::enums::{ArtifactKind, ArtifactScope, SignalClass, ThreatCategory};

pub fn artifact_scope_for_kind(artifact_kind: ArtifactKind) -> ArtifactScope {
    match artifact_kind {
        ArtifactKind::SkillDocument
        | ArtifactKind::AgentInstruction
        | ArtifactKind::PromptPackDocument
        | ArtifactKind::McpServerManifest => ArtifactScope::AgentEntrypoint,
        ArtifactKind::PackageManifest | ArtifactKind::Lockfile | ArtifactKind::GenericArtifact => {
            ArtifactScope::PackageRootArtifact
        }
        ArtifactKind::ReferencedArtifact | ArtifactKind::CodeSnippet => {
            ArtifactScope::SupportingArtifact
        }
    }
}

pub fn signal_class_for(category: ThreatCategory) -> SignalClass {
    match category {
        ThreatCategory::ScopeCreep => SignalClass::Hygiene,
        ThreatCategory::SupplyChain => SignalClass::SuspiciousPackageBehavior,
        ThreatCategory::RemoteExec
        | ThreatCategory::CredentialExposure
        | ThreatCategory::DataExfiltration
        | ThreatCategory::PrivilegeEscalation
        | ThreatCategory::UnsafeBinary => SignalClass::MaliciousBehavior,
        ThreatCategory::PersistentPromptTampering
        | ThreatCategory::ToolAbuse
        | ThreatCategory::AutonomyEscalation
        | ThreatCategory::Obfuscation
        | ThreatCategory::SocialManipulation => SignalClass::SuspiciousPackageBehavior,
        ThreatCategory::PersuasiveLanguage | ThreatCategory::Generic => SignalClass::ReviewSignal,
    }
}
