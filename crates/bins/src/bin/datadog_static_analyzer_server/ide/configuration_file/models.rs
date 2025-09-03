use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct IgnoreRuleRequest {
    pub rule: String,
    #[serde(rename = "configuration")]
    pub configuration_base64: String,
    pub encoded: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct AddRuleSetsRequest {
    pub rulesets: Vec<String>,
    #[serde(rename = "configuration")]
    pub configuration_base64: Option<String>,
    pub encoded: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct GetRulesetsRequest {
    #[serde(rename = "configuration")]
    pub configuration_base64: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct CanOnboardRequest {
    #[serde(rename = "configuration")]
    pub configuration_base64: String,
}
