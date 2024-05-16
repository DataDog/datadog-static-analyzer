use crate::arguments::ArgumentProvider;
use crate::model::config_file::ConfigFile;
use crate::model::rule::{RuleCategory, RuleSeverity};
use crate::path_restrictions::PathRestrictions;
use crate::rule_overrides::RuleOverrides;
use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Default, Clone)]
pub struct RulesConfigProvider {
    path_restrictions: PathRestrictions,
    argument_provider: ArgumentProvider,
    rule_overrides: RuleOverrides,
}

impl RulesConfigProvider {
    pub fn from_config(cfg: &ConfigFile) -> Self {
        RulesConfigProvider {
            path_restrictions: PathRestrictions::from_ruleset_configs(&cfg.rulesets),
            argument_provider: ArgumentProvider::from(cfg),
            rule_overrides: RuleOverrides::from_config_file(cfg),
        }
    }

    pub fn for_file(&self, file_path: &str) -> RulesConfig {
        RulesConfig {
            file_name: file_path.to_string(),
            provider: &self,
        }
    }

    pub fn add_argument(&mut self, rule_name: &str, file_path: &str, argument: &str, value: &str) {
        self.argument_provider
            .add_argument(rule_name, file_path, argument, value)
    }
}

pub struct RulesConfig<'a> {
    file_name: String,
    provider: &'a RulesConfigProvider,
}

impl<'a> RulesConfig<'a> {
    pub fn is_rule_enabled(&self, rule_name: &str) -> bool {
        self.provider
            .path_restrictions
            .rule_applies(rule_name, &self.file_name)
    }

    pub fn arguments(&self, rule_name: &str) -> HashMap<String, String> {
        self.provider
            .argument_provider
            .get_arguments(&self.file_name, rule_name)
    }

    pub fn severity(&self, rule_name: &str) -> Option<RuleSeverity> {
        self.provider.rule_overrides.severity(rule_name)
    }

    pub fn category(&self, rule_name: &str) -> Option<RuleCategory> {
        self.provider.rule_overrides.category(rule_name)
    }
}

impl<'a> Default for RulesConfig<'a> {
    fn default() -> Self {
        static PROVIDER: OnceLock<RulesConfigProvider> = OnceLock::new();
        let provider = PROVIDER.get_or_init(RulesConfigProvider::default);
        RulesConfig {
            file_name: "".to_string(),
            provider,
        }
    }
}
