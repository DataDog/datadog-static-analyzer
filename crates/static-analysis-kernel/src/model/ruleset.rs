use crate::model::rule::Rule;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Clone, Debug, Serialize)]
pub struct RuleSet {
    pub name: String,
    pub description: Option<String>,
    rules: Vec<Rule>,
    /// A private field to prevent this struct from being created manually. Use [`RuleSet::new`] instead.
    _private: std::marker::PhantomData<()>,
}

impl RuleSet {
    /// Creates a new `RuleSet` from the provided rules, ensuring that the name of each rule
    /// has the ruleset id prepended in the format `ruleset_id/rule_name`.
    pub fn new(
        ruleset_id: impl Into<String>,
        description: Option<String>,
        mut rules: Vec<Rule>,
    ) -> Self {
        let ruleset_id = ruleset_id.into();
        let expected_start = format!("{ruleset_id}/");

        for rule in &mut rules {
            // Ensure the rule's name has this ruleset's id prepended:
            if !ruleset_id.is_empty() && !rule.name.starts_with(&expected_start) {
                rule.name = format!("{expected_start}{}", rule.name);
            }
            rule.fix_cwe();
        }
        Self {
            name: ruleset_id,
            description,
            rules,
            _private: std::marker::PhantomData,
        }
    }

    /// Returns a list of the rules within this ruleset.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Consumes the `RuleSet`, returning its rules.
    pub fn into_rules(self) -> Vec<Rule> {
        self.rules
    }
}

impl<'de> Deserialize<'de> for RuleSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// A copy of [`RuleSet`] with a default Deserialize impl.
        #[derive(Deserialize)]
        struct Helper {
            name: String,
            description: Option<String>,
            rules: Vec<Rule>,
        }
        Helper::deserialize(deserializer)
            .map(|ruleset| RuleSet::new(ruleset.name, ruleset.description, ruleset.rules))
    }
}

#[cfg(test)]
mod tests {
    use super::RuleSet;
    use crate::model::common::Language;
    use crate::model::rule::{Rule, RuleCategory, RuleSeverity, RuleType};

    /// A shorthand function to create a rule with the given name.
    fn rule_with_name(name: &str) -> Rule {
        Rule {
            name: name.to_string(),
            short_description_base64: None,
            description_base64: None,
            category: RuleCategory::BestPractices,
            severity: RuleSeverity::Error,
            language: Language::Csharp,
            rule_type: RuleType::TreeSitterQuery,
            entity_checked: None,
            code_base64: "".to_string(),
            cwe: None,
            checksum: "".to_string(),
            pattern: None,
            tree_sitter_query_base64: None,
            arguments: vec![],
            tests: vec![],
            is_testing: false,
        }
    }

    /// Returns an in-order list of rule names from the ruleset.
    fn rule_names(ruleset: &RuleSet) -> Vec<&str> {
        ruleset
            .rules
            .iter()
            .map(|r| r.name.as_str())
            .collect::<Vec<_>>()
    }

    /// A [`RuleSet`] with a non-empty id prepends rules with its id.
    #[test]
    fn ruleset_rule_names() {
        let rules = vec![
            rule_with_name("rule-1"),
            rule_with_name("rule-2"),
            rule_with_name("rs-id/rule-3"),
        ];
        let ruleset = RuleSet::new("rs-id", None, rules);
        assert_eq!(
            rule_names(&ruleset),
            vec!["rs-id/rule-1", "rs-id/rule-2", "rs-id/rule-3"]
        );
    }

    #[test]
    fn ruleset_blank_id_rule_names() {
        let rules = vec![
            rule_with_name("rule-1"),
            rule_with_name("rule-2"),
            rule_with_name("rs-id/rule-3"),
        ];
        let ruleset = RuleSet::new("", None, rules);
        assert_eq!(
            rule_names(&ruleset),
            vec!["rule-1", "rule-2", "rs-id/rule-3"]
        );
    }
}
