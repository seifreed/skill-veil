use super::parser::parse_rules_file;
use super::schema::Rule;
use super::RuleError;

const OFFICIAL_CORE_RULES_YAML: &str = include_str!("../../resources/official/core.yaml");
const OFFICIAL_BEHAVIORAL_RULES_YAML: &str =
    include_str!("../../resources/official/behavioral.yaml");

pub(super) fn get_builtin_rules() -> Result<Vec<Rule>, RuleError> {
    let mut rules = Vec::new();
    for embedded_pack in [OFFICIAL_CORE_RULES_YAML, OFFICIAL_BEHAVIORAL_RULES_YAML] {
        rules.extend(parse_rules_file(embedded_pack)?);
    }
    Ok(rules)
}
