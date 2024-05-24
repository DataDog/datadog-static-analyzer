use std::env;

use crate::constants::{
    DATADOG_HEADER_API_KEY, DATADOG_HEADER_APP_KEY, DATADOG_HEADER_JWT_TOKEN, HEADER_CONTENT_TYPE,
    HEADER_CONTENT_TYPE_APPLICATION_JSON,
};
use anyhow::{anyhow, Result};
use kernel::model::rule::Rule;
use kernel::model::ruleset::RuleSet;
use reqwest::blocking::RequestBuilder;
use uuid::Uuid;

use crate::model::datadog_api::{
    ApiResponse, ApiResponseDefaultRuleset, DiffAwareData, DiffAwareRequest,
    DiffAwareRequestArguments, DiffAwareRequestData, DiffAwareRequestDataAttributes,
    DiffAwareResponse,
};

const STAGING_DATADOG_HOSTNAME: &str = "api.datad0g.com";
const DEFAULT_DATADOG_HOSTNAME: &str = "api.datadoghq.com";

const DEFAULT_RULESETS_LANGUAGES: &[&str] = &[
    "CSHARP",
    "DOCKERFILE",
    "GO",
    "JAVA",
    "JAVASCRIPT",
    "KOTLIN",
    "PYTHON",
    "RUBY",
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
pub fn get_datadog_variable_value(variable: &str) -> Result<String> {
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
    Err(anyhow!("cannot find variable DD_{}", variable))
}

// If a DD_HOSTNAME envvar has been specified, use it; otherwise, use the staging hostname
// if use_staging is true; otherwise, use the DD_SITE envvar with 'api.' prepended;
// otherwise, use the default hostname.
fn get_datadog_hostname(use_staging: bool) -> String {
    if let Ok(hostname) = get_datadog_variable_value("HOSTNAME") {
        hostname
    } else if use_staging {
        STAGING_DATADOG_HOSTNAME.to_string()
    } else if let Ok(site) = get_datadog_variable_value("SITE") {
        format!("api.{}", site).to_string()
    } else {
        DEFAULT_DATADOG_HOSTNAME.to_string()
    }
}

// Returns a RequestBuilder for the given API path.
fn make_request(path: &str, use_staging: bool, require_keys: bool) -> Result<RequestBuilder> {
    let request_builder = reqwest::blocking::Client::new()
        .get(format!(
            "https://{}/api/v2/static-analysis/{}",
            get_datadog_hostname(use_staging),
            path
        ))
        .header(HEADER_CONTENT_TYPE, HEADER_CONTENT_TYPE_APPLICATION_JSON);

    let api_key = get_datadog_variable_value("API_KEY");
    let app_key = get_datadog_variable_value("APP_KEY");
    match (api_key, app_key) {
        (Ok(apik), Ok(appk)) => Ok(request_builder
            .header(DATADOG_HEADER_API_KEY, apik)
            .header(DATADOG_HEADER_APP_KEY, appk)),
        (apir, appr) => match get_datadog_variable_value("JWT_TOKEN") {
            Ok(jwtt) => Ok(request_builder.header(DATADOG_HEADER_JWT_TOKEN, jwtt)),
            Err(_) if !require_keys => Ok(request_builder),
            Err(jwte) => Err(apir.err().or(appr.err()).unwrap_or(jwte)),
        },
    }
}

// get rules from one ruleset at datadog
// it connects to the API using the DD_SITE, DD_APP_KEY and DD_API_KEY and retrieve
// the rulesets. We then extract all the rulesets
pub fn get_ruleset(ruleset_name: &str, use_staging: bool) -> Result<RuleSet> {
    let path = format!(
        "rulesets/{}?include_tests=false&include_testing_rules=true",
        ruleset_name
    );
    let server_response = make_request(&path, use_staging, false)?
        .send()
        .expect("error when querying the datadog server");

    let response_text = &server_response.text()?;
    let api_response = serde_json::from_str::<ApiResponse>(response_text);

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
            eprintln!("{}", response_text);
            Err(anyhow!("error {:?}", e))
        }
    }
}

pub fn get_default_rulesets_name_for_language(
    language: String,
    use_staging: bool,
) -> Result<Vec<String>> {
    let request_builder = make_request(
        &format!("default-rulesets/{}", language),
        use_staging,
        false,
    )?
    .header(HEADER_CONTENT_TYPE, HEADER_CONTENT_TYPE_APPLICATION_JSON);

    let server_response = request_builder.send()?;

    let response_text = &server_response.text()?;
    let api_response = serde_json::from_str::<ApiResponseDefaultRuleset>(response_text);

    match api_response {
        Ok(d) => Ok(d.data.attributes.rulesets),
        Err(e) => {
            eprintln!(
                "Error when getting the default rulesets for language {} {:?}",
                language, e
            );
            eprintln!("{}", response_text);
            Err(anyhow!("error {:?}", e))
        }
    }
}

/// Get all the default rulesets available at DataDog. Take all the language
/// from `DEFAULT_RULESETS_LANGAGES` and get their rulesets
pub fn get_all_default_rulesets(use_staging: bool) -> Result<Vec<RuleSet>> {
    let mut result: Vec<RuleSet> = vec![];

    for language in DEFAULT_RULESETS_LANGUAGES {
        let ruleset_names =
            get_default_rulesets_name_for_language(language.to_string(), use_staging)?;

        for ruleset_name in ruleset_names {
            result.push(get_ruleset(ruleset_name.as_str(), use_staging)?);
        }
    }
    Ok(result)
}

/// Get diff-aware data from Datadog. In order to be able to perform this,
/// we need to ensure that
///   1. We are scanning a Git Repository
///   2. We have API Keys for the user
/// When we issue the request, we pass
///   - repository url
///   - current sha
///   - current branch
///   - config hash
///
/// If we can do a diff-aware scan, we will then receive the list of files
/// to analyze and the base sha (e.g. the sha we used in the past to find
/// the list of files). This information will later be added in the
/// results.
pub fn get_diff_aware_information(arguments: &DiffAwareRequestArguments) -> Result<DiffAwareData> {
    let request_uuid = Uuid::new_v4().to_string();

    let request_payload = DiffAwareRequest {
        data: DiffAwareRequestData {
            id: request_uuid.clone(),
            request_type: "diff_aware_request".to_string(),
            attributes: DiffAwareRequestDataAttributes {
                id: request_uuid.clone(),
                repository_url: arguments.repository_url.clone(),
                sha: arguments.sha.clone(),
                branch: arguments.branch.clone(),
                config_hash: arguments.config_hash.clone(),
            },
        },
    };

    let server_response = make_request("analysis/diff-aware", false, true)?
        .json(&request_payload)
        .send()
        .expect("error when querying the datadog server");

    let status = server_response.status();
    let response_text = &server_response.text()?;
    let api_response = serde_json::from_str::<DiffAwareResponse>(response_text);

    if !&status.is_success() {
        return Err(anyhow!("server returned error {}", &status.as_u16()));
    }

    match api_response {
        Ok(d) => Ok(DiffAwareData {
            base_sha: d.data.attributes.base_sha,
            files: d.data.attributes.files,
        }),
        Err(e) => {
            eprintln!("Error when issuing the diff-aware request {:?}", e);
            Err(anyhow!("error {:?}", e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_datadog_hostname() {
        assert_eq!(get_datadog_hostname(true), STAGING_DATADOG_HOSTNAME);
        assert_eq!(get_datadog_hostname(false), DEFAULT_DATADOG_HOSTNAME);
    }
}
