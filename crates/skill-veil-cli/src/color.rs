use crate::cli_args::ColorChoiceArg;
use skill_veil_core::{PackageHealth, RecommendedAction, Severity, Verdict};

#[derive(Copy, Clone)]
pub(crate) struct ColorMode {
    enabled: bool,
}

impl ColorMode {
    /// Build a `ColorMode` from the `--color` flag.
    ///
    /// Honors the [NO_COLOR](https://no-color.org/) standard: any non-empty
    /// `NO_COLOR` env var disables ANSI colors in `Auto` mode. `Always`
    /// still wins over `NO_COLOR` because the user asked for it explicitly.
    pub(crate) fn from_choice(choice: ColorChoiceArg, is_terminal: bool) -> Self {
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        let enabled = match choice {
            ColorChoiceArg::Auto => is_terminal && !no_color,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serialize env mutation across tests so concurrent runs don't observe
    // each other's NO_COLOR state.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn no_color_env_disables_auto_mode_on_tty() {
        let _g = ENV_LOCK.lock().expect("ENV_LOCK poisoned");
        std::env::set_var("NO_COLOR", "1");
        let mode = ColorMode::from_choice(ColorChoiceArg::Auto, /* is_terminal */ true);
        assert!(!mode.enabled, "NO_COLOR must disable Auto on a TTY");
        std::env::remove_var("NO_COLOR");
    }

    #[test]
    fn empty_no_color_does_not_disable() {
        let _g = ENV_LOCK.lock().expect("ENV_LOCK poisoned");
        std::env::set_var("NO_COLOR", "");
        let mode = ColorMode::from_choice(ColorChoiceArg::Auto, true);
        assert!(mode.enabled, "empty NO_COLOR is documented as not enabled");
        std::env::remove_var("NO_COLOR");
    }

    #[test]
    fn always_overrides_no_color() {
        let _g = ENV_LOCK.lock().expect("ENV_LOCK poisoned");
        std::env::set_var("NO_COLOR", "1");
        let mode = ColorMode::from_choice(ColorChoiceArg::Always, false);
        assert!(
            mode.enabled,
            "explicit --color=always must win over NO_COLOR"
        );
        std::env::remove_var("NO_COLOR");
    }

    #[test]
    fn never_forces_disabled_regardless_of_env() {
        let _g = ENV_LOCK.lock().expect("ENV_LOCK poisoned");
        std::env::remove_var("NO_COLOR");
        let mode = ColorMode::from_choice(ColorChoiceArg::Never, true);
        assert!(!mode.enabled);
    }
}
