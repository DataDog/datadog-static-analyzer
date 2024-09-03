use std::env;

use crate::{
    constants::{
        DATADOG_HEADER_API_KEY, DATADOG_HEADER_APP_KEY, DATADOG_HEADER_JWT_TOKEN,
        HEADER_CONTENT_TYPE, HEADER_CONTENT_TYPE_APPLICATION_JSON,
    },
    model::datadog_api::APIErrorResponse,
};
use anyhow::{anyhow, Result};
use kernel::model::rule::Rule;
use kernel::model::ruleset::RuleSet;
use reqwest::blocking::RequestBuilder;
use secrets::model::secret_rule::SecretRule;
use uuid::Uuid;

use crate::model::datadog_api::{
    ApiResponseDefaultRuleset, ConfigRequest, ConfigRequestData, ConfigRequestDataAttributes,
    ConfigResponse, DiffAwareData, DiffAwareRequest, DiffAwareRequestArguments,
    DiffAwareRequestData, DiffAwareRequestDataAttributes, DiffAwareResponse,
    StaticAnalysisRulesAPIResponse, StaticAnalysisSecretsAPIResponse,
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
    "PHP",
    "YAML",
];

// Get secrets rules from the static analysis API
pub fn get_secrets_rules(use_staging: bool) -> Result<Vec<SecretRule>> {
    let req = make_request(RequestMethod::Get, "secrets/rules", use_staging, true);
    let server_response = perform_request(req?, "secrets/rules", false)?;

    let status_code = server_response.status();
    let response_text = &server_response.text()?;

    if !status_code.is_success() {
        let error = serde_json::from_str::<APIErrorResponse>(response_text)?;
        let error_msg = error.errors.into_iter().next().map_or_else(
            || format!("Unknown error {status_code}"),
            |e| format!("Error: {}", e.detail.unwrap_or(e.title)),
        );
        eprintln!("{error_msg}");
        return Err(anyhow!(error_msg));
    }

    let api_response = serde_json::from_str::<StaticAnalysisSecretsAPIResponse>(response_text);

    match api_response {
        Ok(d) => Ok(d
            .data
            .iter()
            .map(|v| SecretRule {
                id: v.id.clone(),
                name: v.attributes.name.clone(),
                description: v.attributes.description.clone(),
                pattern: v.attributes.pattern.clone(),
                default_included_keywords: v
                    .attributes
                    .default_included_keywords
                    .clone()
                    .unwrap_or_default(),
            })
            .collect()),
        Err(e) => {
            eprintln!("Error when parsing the secret rules {e:?}");
            eprintln!("{response_text}");
            Err(anyhow!("error {e:?}"))
        }
    }
}

// Get all the rules from different rulesets from Datadog
pub fn get_rules_from_rulesets(
    rulesets_name: &[String],
    use_staging: bool,
    debug: bool,
) -> Result<Vec<Rule>> {
    let mut rules: Vec<Rule> = Vec::new();
    for ruleset_name in rulesets_name {
        rules.extend(get_ruleset(ruleset_name, use_staging, debug)?.rules);
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

enum RequestMethod {
    Get,
    Post,
}

/// Return `true` if the customer configured their environment in a way that
pub fn should_use_datadog_backend() -> bool {
    get_datadog_variable_value("API_KEY").is_ok()
}

// Returns a RequestBuilder for the given API path.
fn make_request(
    method: RequestMethod,
    path: &str,
    use_staging: bool,
    require_keys: bool,
) -> Result<RequestBuilder> {
    let url = format!(
        "https://{}/api/v2/static-analysis/{}",
        get_datadog_hostname(use_staging),
        path
    );
    let request_builder = match method {
        RequestMethod::Get => reqwest::blocking::Client::new().get(url),
        RequestMethod::Post => reqwest::blocking::Client::new().post(url),
    }
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

fn perform_request(
    request_builder: RequestBuilder,
    path: &str,
    debug: bool,
) -> Result<reqwest::blocking::Response> {
    let mut server_response = None;
    let mut retry_time = std::time::Duration::from_secs(1);
    for i in 0..5 {
        match request_builder
            .try_clone()
            .expect("Cloning a request builder should not fail")
            .send()
        {
            Ok(r) => {
                server_response = Some(Ok(r));
                break;
            }
            Err(e) => {
                if debug {
                    eprintln!(
                        "[Attempt #{}] Error when querying the datadog server at {path}: {e}",
                        i + 1
                    );
                    eprintln!("Retrying in {} seconds", retry_time.as_secs());
                }
                server_response = Some(Err(e));
                std::thread::sleep(retry_time);
                retry_time *= 2; // Exponential backoff
            }
        }
    }

    server_response
        .expect("server_response should have been set")
        .map_err(|e| anyhow!("Error when querying the datadog server at {path}: {e}"))
}

// get rules from one ruleset at datadog
// it connects to the API using the DD_SITE, DD_APP_KEY and DD_API_KEY and retrieve
// the rulesets. We then extract all the rulesets
pub fn get_ruleset(ruleset_name: &str, use_staging: bool, debug: bool) -> Result<RuleSet> {
    let path = format!("rulesets/{ruleset_name}?include_tests=false&include_testing_rules=true");
    let req = make_request(RequestMethod::Get, &path, use_staging, false)?;
    let server_response = perform_request(req, &path, debug)?;

    let status_code = server_response.status();
    let response_text = &server_response.text()?;

    if !status_code.is_success() {
        let error = serde_json::from_str::<APIErrorResponse>(response_text)?;
        let error_msg = error.errors.into_iter().next().map_or_else(
            || format!("Unknown error {status_code}"),
            |e| format!("Error: {}", e.detail.unwrap_or(e.title)),
        );
        eprintln!("{error_msg}");
        return Err(anyhow!(error_msg));
    }

    let api_response = serde_json::from_str::<StaticAnalysisRulesAPIResponse>(response_text);

    match api_response {
        Ok(d) => {
            let mut ruleset = d.clone().into_ruleset();
            // Let's make sure if the CWE is an empty string, we set it to none
            let fixed_rules = ruleset.rules.iter_mut().map(|r| r.fix_cwe()).collect();
            ruleset.rules = fixed_rules;
            Ok(ruleset)
        }
        Err(e) => {
            eprintln!("Error when parsing the ruleset {ruleset_name} {e:?}");
            eprintln!("{response_text}");
            Err(anyhow!("error {e:?}"))
        }
    }
}

pub fn get_default_rulesets_name_for_language(
    language: String,
    use_staging: bool,
    debug: bool,
) -> Result<Vec<String>> {
    let path = format!("default-rulesets/{}", language);

    let request_builder = make_request(RequestMethod::Get, &path, use_staging, false)?
        .header(HEADER_CONTENT_TYPE, HEADER_CONTENT_TYPE_APPLICATION_JSON);

    let server_response = perform_request(request_builder, &path, debug)?;

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
pub fn get_all_default_rulesets(use_staging: bool, debug: bool) -> Result<Vec<RuleSet>> {
    let mut result: Vec<RuleSet> = vec![];

    for language in DEFAULT_RULESETS_LANGUAGES {
        let ruleset_names =
            get_default_rulesets_name_for_language(language.to_string(), use_staging, debug)?;

        for ruleset_name in ruleset_names {
            result.push(get_ruleset(ruleset_name.as_str(), use_staging, debug)?);
        }
    }
    Ok(result)
}

/// Get diff-aware data from Datadog. In order to be able to perform this,
/// we need to ensure that
///   1. We are scanning a Git Repository
///   2. We have API Keys for the user
///
///   When we issue the request, we pass
///   - repository url
///   - current sha
///   - current branch
///   - config hash
///
/// If we can do a diff-aware scan, we will then receive the list of files
/// to analyze and the base sha (e.g. the sha we used in the past to find
/// the list of files). This information will later be added in the
/// results.
pub fn get_diff_aware_information(
    arguments: &DiffAwareRequestArguments,
    debug: bool,
) -> Result<DiffAwareData> {
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

    let path = "analysis/diff-aware";
    let req = make_request(RequestMethod::Post, path, false, true)?.json(&request_payload);
    let server_response = perform_request(req, path, debug)?;

    let status_code = server_response.status();
    let response_text = &server_response.text()?;

    let api_response = serde_json::from_str::<DiffAwareResponse>(response_text);

    if !&status_code.is_success() {
        return Err(anyhow!("server returned error {}", &status_code.as_u16()));
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

/// Get remote configuration from the Databdog backend
pub fn get_remote_configuration(
    repository_url: String,
    config_base64: Option<String>,
    debug: bool,
) -> Result<String> {
    let request_payload = ConfigRequest {
        data: ConfigRequestData {
            request_type: "config".to_string(),
            attributes: ConfigRequestDataAttributes {
                repository: repository_url.clone(),
                config_base64: config_base64.clone(),
            },
        },
    };

    let path = "config/client";
    let req = make_request(RequestMethod::Post, path, false, true)?.json(&request_payload);
    let server_response = perform_request(req, path, debug)?;

    let status_code = server_response.status();
    let response_text = &server_response.text()?;

    let api_response = serde_json::from_str::<ConfigResponse>(response_text);

    if !status_code.is_success() {
        return Err(anyhow!("server returned error {}", status_code.as_u16()));
    }

    match api_response {
        Ok(d) => Ok(d.data.attributes.config_base64),
        Err(e) => {
            eprintln!("Error when issuing the config request {:?}", e);
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
