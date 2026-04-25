use super::parser::parse_rules_file;
use super::schema::Rule;
use super::RuleError;

const OFFICIAL_CORE_RULES_YAML: &str = include_str!("../../resources/official/core.yaml");
const OFFICIAL_BEHAVIORAL_RULES_YAML: &str =
    include_str!("../../resources/official/behavioral.yaml");
const SKILL_VEIL_SUPPLEMENTARY_RULES: &str = include_str!("../builtin_rules.yaml");

/// Load every embedded rule pack that ships with the binary, rejecting any
/// duplicate ids across the packs. Because all three YAMLs are under our
/// own control, a duplicate is always a developer mistake — silent dedup
/// would hide divergent definitions and make verdicts irreproducible.
pub(super) fn get_builtin_rules() -> Result<Vec<Rule>, RuleError> {
    let packs: &[(&'static str, &'static str)] = &[
        ("official/core.yaml", OFFICIAL_CORE_RULES_YAML),
        ("official/behavioral.yaml", OFFICIAL_BEHAVIORAL_RULES_YAML),
        ("src/builtin_rules.yaml", SKILL_VEIL_SUPPLEMENTARY_RULES),
    ];
    let mut seen: std::collections::HashMap<String, &'static str> =
        std::collections::HashMap::new();
    let mut rules = Vec::new();
    for (pack_name, body) in packs {
        for rule in parse_rules_file(body)? {
            if let Some(prev_pack) = seen.get(&rule.id) {
                return Err(RuleError::DuplicateBuiltinRule {
                    id: rule.id.clone(),
                    first: (*prev_pack).to_string(),
                    second: (*pack_name).to_string(),
                });
            }
            seen.insert(rule.id.clone(), pack_name);
            rules.push(rule);
        }
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_have_no_internal_duplicate_ids() {
        // Regression guard: if someone re-introduces a duplicate across the
        // three embedded packs, this test fails at build time instead of
        // silently dropping a rule at runtime.
        let result = get_builtin_rules();
        assert!(
            result.is_ok(),
            "built-in rule packs must not contain duplicate ids; got {:?}",
            result.err(),
        );
    }
}
