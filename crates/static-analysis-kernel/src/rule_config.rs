use crate::arguments::ArgumentProvider;
use crate::model::config_file::{ConfigFile, SplitPath};
use crate::model::rule::{RuleCategory, RuleSeverity};
use crate::path_restrictions::PathRestrictions;
use crate::rule_overrides::RuleOverrides;
use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Default, Clone)]
pub struct RuleConfigProvider {
    path_restrictions: PathRestrictions,
    argument_provider: ArgumentProvider,
    rule_overrides: RuleOverrides,
}

impl RuleConfigProvider {
    pub fn from_config(cfg: &ConfigFile) -> RuleConfigProvider {
        RuleConfigProvider {
            path_restrictions: PathRestrictions::from_ruleset_configs(&cfg.rulesets),
            argument_provider: ArgumentProvider::from(cfg),
            rule_overrides: RuleOverrides::from_config_file(cfg),
        }
    }

    pub fn config_for_file(&self, file_path: &str) -> RuleConfig {
        RuleConfig {
            provider: self,
            file_path: file_path.to_string(),
            split_path: SplitPath::from_string(file_path),
        }
    }
}

pub struct RuleConfig<'a> {
    provider: &'a RuleConfigProvider,
    file_path: String,
    split_path: SplitPath,
}

impl<'a> RuleConfig<'a> {
    pub fn rule_is_enabled(&self, rule_name: &str) -> bool {
        self.provider
            .path_restrictions
            .rule_applies(rule_name, &self.file_path)
    }

    pub fn get_arguments(&self, rule_name: &str) -> HashMap<String, String> {
        self.provider
            .argument_provider
            .get_arguments(&self.split_path, rule_name)
    }

    pub fn get_severity(&self, rule_name: &str) -> Option<RuleSeverity> {
        self.provider
            .rule_overrides
            .severity(&self.split_path, rule_name)
    }

    pub fn get_category(&self, rule_name: &str) -> Option<RuleCategory> {
        self.provider.rule_overrides.category(rule_name)
    }
}

impl Default for RuleConfig<'static> {
    fn default() -> Self {
        static PROVIDER: OnceLock<RuleConfigProvider> = OnceLock::new();
        PROVIDER
            .get_or_init(RuleConfigProvider::default)
            .config_for_file("")
    }
}
