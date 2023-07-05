use crate::model::rule::Rule;
use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Debug, Serialize)]
pub struct RuleSet {
    pub name: String,
    pub description: Option<String>,
    pub rules: Vec<Rule>,
}
