use std::env;

use anyhow::{anyhow, Result};
use kernel::model::rule::Rule;
use kernel::model::ruleset::RuleSet;

use crate::model::datadog_api::{ApiResponse, ApiResponseDefaultRuleset};

const STAGING_DATADOG_SITE: &str = "datad0g.com";
const DEFAULT_DATADOG_SITE: &str = "datadoghq.com";

const DEFAULT_RULESETS_LANGUAGES: &[&str] = &[
    "CSHARP",
    "DOCKERFILE",
    "GO",
    "JAVA",
    "JAVASCRIPT",
    "KOTLIN",
    "PYTHON",
    "TYPESCRIPT",
];

// Get all the rules from different rulesets from Datadog
pub fn get_rules_from_rulesets(rulesets_name: &[String], use_staging: bool) -> Result<Vec<Rule>> {
    let mut rules: Vec<Rule> = Vec::new();
    for ruleset_name in rulesets_name {
        rules.extend(get_ruleset(ruleset_name, use_staging)?.rules);
    }
    Ok(rules)
}

// Get environment variables for Datadog. First try to get the variables
// prefixed with DD_ and then, try DATADOG_.
// If nothing works, just returns an error.
pub fn get_datadog_variable_value(variable: &str) -> anyhow::Result<String> {
    let prefixes = vec!["DD", "DATADOG"];
    for prefix in prefixes {
        let name = format!("{}_{}", prefix, variable);
        let var_content = env::var(name);
        if let Ok(var_value) = var_content {
            if var_value.is_empty() {
                continue;
            }
            return Ok(var_value);
        }
    }
    Err(anyhow!("cannot find variable value"))
}

// if we use staging, override the value.
// otherwise, use the DD_SITE variable or the default site
fn get_datadog_site(use_staging: bool) -> String {
    if use_staging {
        STAGING_DATADOG_SITE.to_string()
    } else {
        get_datadog_variable_value("SITE").unwrap_or(DEFAULT_DATADOG_SITE.to_string())
    }
}

// get rules from one ruleset at datadog
// it connects to the API using the DD_SITE, DD_APP_KEY and DD_API_KEY and retrieve
// the rulesets. We then extract all the rulesets
pub fn get_ruleset(ruleset_name: &str, use_staging: bool) -> Result<RuleSet> {
    let site = get_datadog_site(use_staging);
    let app_key = get_datadog_variable_value("APP_KEY");
    let api_key = get_datadog_variable_value("API_KEY");

    let url = format!(
        "https://api.{}/api/v2/static-analysis/rulesets/{}?include_tests=false",
        site, ruleset_name
    );

    let request_builder = reqwest::blocking::Client::new()
        .get(url)
        .header("Content-Type", "application/json");

    // only add datadog credentials if both app-key and api-keys are defined.
    let request_builder_with_auth = match (app_key, api_key) {
        (Ok(appk), Ok(apik)) => request_builder
            .header("dd-api-key", apik)
            .header("dd-application-key", appk),
        _ => request_builder,
    };

    let server_response = request_builder_with_auth
        .send()
        .expect("error when querying the datadog server");

    let response_text = &server_response.text();
    let api_response =
        serde_json::from_str::<ApiResponse>(response_text.as_ref().unwrap().as_str());

    match api_response {
        Ok(d) => {
            let mut ruleset = d.clone().into_ruleset();
            // Let's make sure if the CWE is an empty string, we set it to none
            let fixed_rules = ruleset.rules.iter_mut().map(|r| r.fix_cwe()).collect();
            ruleset.rules = fixed_rules;
            Ok(ruleset)
        }
        Err(e) => {
            eprintln!("Error when parsing the ruleset {} {:?}", ruleset_name, e);
            eprintln!("{}", response_text.as_ref().unwrap().as_str());
            Err(anyhow!("error {:?}", e))
        }
    }
}

pub fn get_default_rulesets_name_for_language(
    language: String,
    use_staging: bool,
) -> Result<Vec<String>> {
    let site = get_datadog_site(use_staging);

    let url = format!(
        "https://api.{}/api/v2/static-analysis/default-rulesets/{}",
        site, language
    );

    let request_builder = reqwest::blocking::Client::new()
        .get(url)
        .header("Content-Type", "application/json");

    let server_response = request_builder
        .send()
        .expect("error when querying the datadog server");

    let response_text = &server_response.text();
    let api_response =
        serde_json::from_str::<ApiResponseDefaultRuleset>(response_text.as_ref().unwrap().as_str());

    match api_response {
        Ok(d) => Ok(d.data.attributes.rulesets),
        Err(e) => {
            eprintln!(
                "Error when getting the default rulesets for language {} {:?}",
                language, e
            );
            eprintln!("{}", response_text.as_ref().unwrap().as_str());
            Err(anyhow!("error {:?}", e))
        }
    }
}

/// Get all the default rulesets available at DataDog. Take all the language
/// from `DEFAULT_RULESETS_LANGAGES` and get their rulesets
pub fn get_all_default_rulesets(use_staging: bool) -> Result<Vec<RuleSet>> {
    let rules: Vec<RuleSet> = DEFAULT_RULESETS_LANGUAGES
        .iter()
        .flat_map(|language| {
            let ruleset_names =
                get_default_rulesets_name_for_language(language.to_string(), use_staging)
                    .expect("fail to get default rulesets");
            let rulesets: Vec<RuleSet> = ruleset_names
                .iter()
                .map(|ruleset| get_ruleset(ruleset, use_staging).expect("cannot fetch ruleset"))
                .collect();
            rulesets
        })
        .collect();
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_datadog_site() {
        assert_eq!(get_datadog_site(true), STAGING_DATADOG_SITE);
        assert_eq!(get_datadog_site(false), DEFAULT_DATADOG_SITE);
    }

    #[test]
    fn test_get_default_rulesets() {
        let default_ruleset =
            get_all_default_rulesets(false).expect("get default rulesets from API");
        assert!(default_ruleset.len() >= 24);
        let rules_count: usize = default_ruleset.iter().map(|r| r.rules.len()).sum();
        assert!(rules_count > 100);
    }
}
