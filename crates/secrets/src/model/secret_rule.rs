// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use common::model::diff_aware::DiffAware;
use sds::{MatchAction, ProximityKeywordsConfig, RegexRuleConfig};
use serde::{Deserialize, Serialize};

const DEFAULT_LOOK_AHEAD_CHARACTER_COUNT: usize = 30;

// This is the secret rule exposed by SDS
#[derive(Clone, Deserialize, Debug, Serialize)]
pub struct SecretRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub pattern: String,
    pub default_included_keywords: Vec<String>,
}

impl SecretRule {
    /// Convert the rule into a configuration usable by SDS.
    pub fn convert_to_sds_ruleconfig(&self) -> RegexRuleConfig {
        let mut rule_config = RegexRuleConfig::new(&self.pattern).match_action(MatchAction::None);

        if !self.default_included_keywords.is_empty() {
            rule_config = rule_config.proximity_keywords(ProximityKeywordsConfig {
                look_ahead_character_count: DEFAULT_LOOK_AHEAD_CHARACTER_COUNT,
                included_keywords: self.default_included_keywords.clone(),
                excluded_keywords: vec![],
            });
        }

        rule_config
    }
}

impl DiffAware for SecretRule {
    fn generate_diff_aware_digest(&self) -> String {
        format!("{}:{}", self.id, self.pattern).to_string()
    }
}
