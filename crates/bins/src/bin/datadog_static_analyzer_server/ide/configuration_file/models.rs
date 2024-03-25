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
pub struct Version {
    pub version: String,
    #[serde(rename = "staticAnalyzerVersion")]
    pub sa_version: String,
    #[serde(rename = "staticAnalyzerRevision")]
    pub sa_revision: String,
}
