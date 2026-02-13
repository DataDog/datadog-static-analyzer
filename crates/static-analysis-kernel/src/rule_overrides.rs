use crate::config::common::{BySubtree, SplitPath};
use crate::config::file_v2;
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
    pub fn from_config_file(cfg: &file_v2::ConfigFile) -> Self {
        let mut severities = HashMap::<String, BySubtree<RuleSeverity>>::new();
        let mut categories = HashMap::<String, RuleCategory>::new();

        if let Some(ruleset_configs) = &cfg.ruleset_configs {
            for (ruleset_name, cfg) in ruleset_configs {
                for (rule_name, rule) in &cfg.rules {
                    if let Some(sev) = &rule.severity {
                        severities.insert(format!("{ruleset_name}/{rule_name}"), sev.clone());
                    }
                    if let Some(cat) = rule.category {
                        categories.insert(format!("{ruleset_name}/{rule_name}"), cat);
                    }
                }
            }
        }
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
        self.categories.get(rule_name).copied()
    }
}
