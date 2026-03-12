use crate::cli_args::ColorChoiceArg;
use skill_veil_core::{PackageHealth, RecommendedAction, Severity, Verdict};

#[derive(Copy, Clone)]
pub(crate) struct ColorMode {
    enabled: bool,
}

impl ColorMode {
    pub(crate) fn from_choice(choice: ColorChoiceArg, is_terminal: bool) -> Self {
        let enabled = match choice {
            ColorChoiceArg::Auto => is_terminal,
            ColorChoiceArg::Always => true,
            ColorChoiceArg::Never => false,
        };
        Self { enabled }
    }

    fn style(&self, text: impl AsRef<str>, code: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{}\x1b[0m", text.as_ref())
        } else {
            text.as_ref().to_string()
        }
    }

    pub(crate) fn heading(&self, text: impl AsRef<str>) -> String {
        self.style(text, "1;36")
    }

    pub(crate) fn muted(&self, text: impl AsRef<str>) -> String {
        self.style(text, "2")
    }

    pub(crate) fn severity_label(&self, severity: Severity) -> String {
        match severity {
            Severity::Critical => self.style("[CRIT]", "1;97;41"),
            Severity::High => self.style("[HIGH]", "1;31"),
            Severity::Medium => self.style("[MED] ", "1;33"),
            Severity::Low => self.style("[LOW] ", "1;34"),
        }
    }

    pub(crate) fn verdict(&self, verdict: Verdict) -> String {
        match verdict {
            Verdict::Malicious => self.style(verdict.to_string(), "1;31"),
            Verdict::Suspicious => self.style(verdict.to_string(), "1;33"),
            Verdict::Benign => self.style(verdict.to_string(), "1;32"),
        }
    }

    pub(crate) fn action(&self, action: RecommendedAction) -> String {
        match action {
            RecommendedAction::Block => self.style(action.to_string(), "1;31"),
            RecommendedAction::RequireApproval => self.style(action.to_string(), "1;33"),
            RecommendedAction::Log => self.style(action.to_string(), "1;32"),
        }
    }

    pub(crate) fn package_health(&self, health: PackageHealth) -> String {
        match health {
            PackageHealth::Healthy => self.style(health.to_string(), "1;32"),
            PackageHealth::Elevated => self.style(health.to_string(), "1;33"),
            PackageHealth::NeedsReview => self.style(health.to_string(), "1;33"),
        }
    }

    pub(crate) fn blast_radius(&self, level: impl ToString) -> String {
        match level.to_string().as_str() {
            "high" => self.style(level.to_string(), "1;31"),
            "medium" => self.style(level.to_string(), "1;33"),
            _ => self.style(level.to_string(), "1;32"),
        }
    }

    pub(crate) fn scope(&self, text: impl AsRef<str>) -> String {
        self.style(text, "1;35")
    }

    pub(crate) fn rule(&self, text: impl AsRef<str>) -> String {
        self.style(text, "1;34")
    }
}
