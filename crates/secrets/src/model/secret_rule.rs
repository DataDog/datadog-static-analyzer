// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use sds::{MatchAction, RuleConfig};
use serde::{Deserialize, Serialize};

// const SECRET_SEVERITY = Sev

// This is the secret rule exposed by SDS
#[derive(Clone, Deserialize, Debug, Serialize)]
pub struct SecretRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub pattern: String,
}

impl SecretRule {
    /// Convert the rule into a configuration usable by SDS.
    pub fn convert_to_sds_ruleconfig(&self) -> RuleConfig {
        RuleConfig::builder(&self.pattern)
            .match_action(MatchAction::None)
            .build()
    }
}
