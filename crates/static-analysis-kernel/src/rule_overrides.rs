use crate::model::config_file::{BySubtree, ConfigFile, SplitPath};
use crate::model::rule::{RuleCategory, RuleSeverity};
use std::collections::HashMap;

/// User-provided overrides for rule definitions.
#[derive(Default, Clone)]
pub struct RuleOverrides {
    severities: HashMap<String, BySubtree<RuleSeverity>>,
    categories: HashMap<String, RuleCategory>,
}

impl RuleOverrides {
    // Reads the overrides from the configuration file.
    pub fn from_config_file(cfg: &ConfigFile) -> Self {
        let severities: HashMap<String, BySubtree<RuleSeverity>> = cfg
            .rulesets
            .iter()
            .flat_map(|(rs_name, cfg)| {
                cfg.rules.iter().filter_map(move |(rule_name, rule)| {
                    rule.severity
                        .as_ref()
                        .map(|sev| (format!("{}/{}", rs_name, rule_name), sev.clone()))
                })
            })
            .collect();
        let categories: HashMap<String, RuleCategory> = cfg
            .rulesets
            .iter()
            .flat_map(|(rs_name, cfg)| {
                cfg.rules.iter().filter_map(move |(rule_name, rule)| {
                    rule.category
                        .as_ref()
                        .map(|cat| (format!("{}/{}", rs_name, rule_name), *cat))
                })
            })
            .collect();
        RuleOverrides {
            severities,
            categories,
        }
    }

    // Returns the overridden severity for the given rule name, or the original severity if no override exists.
    pub fn severity(&self, file_path: &SplitPath, rule_name: &str) -> Option<RuleSeverity> {
        self.severities
            .get(rule_name)
            .and_then(|s| s.get_ancestor(file_path).cloned())
    }

    // Returns the overridden category for the given rule name, or the original category if no override exists.
    pub fn category(&self, rule_name: &str) -> Option<RuleCategory> {
        self.categories.get(rule_name).cloned()
    }
}
