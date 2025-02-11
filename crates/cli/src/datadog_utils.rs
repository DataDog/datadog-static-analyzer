use std::env;

use crate::datadog_utils::DatadogApiError::{
    CouldNotParseJson, CouldNotParseResponse, CouldNotQuery, ErrorResponse, MissingVariable,
    RulesetNotFound,
};
use crate::model::datadog_api::{
    ApiResponseDefaultRuleset, ConfigRequest, ConfigRequestData, ConfigRequestDataAttributes,
    ConfigResponse, DiffAwareData, DiffAwareRequest, DiffAwareRequestArguments,
    DiffAwareRequestData, DiffAwareRequestDataAttributes, DiffAwareResponse,
    StaticAnalysisRulesAPIResponse, StaticAnalysisSecretsAPIResponse,
};
use crate::{
    constants::{
        DATADOG_HEADER_API_KEY, DATADOG_HEADER_APP_KEY, DATADOG_HEADER_JWT_TOKEN,
        HEADER_CONTENT_TYPE, HEADER_CONTENT_TYPE_APPLICATION_JSON,
    },
    model::datadog_api::APIErrorResponse,
};
use kernel::model::rule::Rule;
use kernel::model::ruleset::RuleSet;
use reqwest::blocking::{RequestBuilder, Response};
use secrets::model::secret_rule::SecretRule;
use thiserror::Error;
use uuid::Uuid;

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

#[derive(Error, Debug)]
pub enum DatadogApiError {
    #[error("Cannot find variable {0}")]
    MissingVariable(String),
    #[error("Ruleset not found: {0}")]
    RulesetNotFound(String),
    #[error("Could not query the DataDog API at {0}: {1}")]
    CouldNotQuery(String, #[source] reqwest::Error),
    #[error("API returned error {0}: {1}")]
    ErrorResponse(u16, String),
    #[error("HTTP response parsing error: {0}")]
    CouldNotParseResponse(#[source] reqwest::Error),
    #[error("JSON parsing error: {0}")]
    CouldNotParseJson(#[source] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, DatadogApiError>;

// Get secrets rules from the static analysis API
pub fn get_secrets_rules(use_staging: bool) -> Result<Vec<SecretRule>> {
    let req = make_request(RequestMethod::Get, "secrets/rules", use_staging, true);
    parse_response(perform_request(req?, "secrets/rules", false)?)
        .inspect_err(|e| eprintln!("Error when parsing the secret rules {e:?}"))
        .map(|d: StaticAnalysisSecretsAPIResponse| {
            d.data
                .into_iter()
                .map(|v| v.try_into().expect("cannot convert rule"))
                .collect()
        })
}

// Get all the rules from different rulesets from Datadog
pub fn get_rules_from_rulesets(
    rulesets_name: &[String],
    use_staging: bool,
    debug: bool,
) -> Result<Vec<Rule>> {
    let mut rules: Vec<Rule> = Vec::new();
    for ruleset_name in rulesets_name {
        rules.extend(get_ruleset(ruleset_name, use_staging, debug)?.into_rules());
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
    Err(MissingVariable(format!("DD_{}", variable)))
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

/// Return `true` if the customer configured their environment in a way that use the datadog backend.
pub fn should_use_datadog_backend() -> bool {
    get_datadog_variable_value("API_KEY").is_ok() || get_datadog_variable_value("JWT_TOKEN").is_ok()
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

fn perform_request(request_builder: RequestBuilder, path: &str, debug: bool) -> Result<Response> {
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
        .map_err(|e| CouldNotQuery(path.to_string(), e))
}

fn parse_response<T>(server_response: Response) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let status_code = server_response.status();
    let response_text = &server_response.text().map_err(CouldNotParseResponse)?;

    if !status_code.is_success() {
        let error =
            serde_json::from_str::<APIErrorResponse>(response_text).map_err(CouldNotParseJson)?;
        let error_msg = error.errors.into_iter().next().map_or_else(
            || "Unknown error".to_string(),
            |e| e.detail.unwrap_or(e.title),
        );
        return Err(ErrorResponse(status_code.as_u16(), error_msg));
    }

    serde_json::from_str::<T>(response_text).map_err(CouldNotParseJson)
}

// get rules from one ruleset at datadog
// it connects to the API using the DD_SITE, DD_APP_KEY and DD_API_KEY and retrieve
// the rulesets. We then extract all the rulesets
pub fn get_ruleset(ruleset_name: &str, use_staging: bool, debug: bool) -> Result<RuleSet> {
    let path = format!("rulesets/{ruleset_name}?include_tests=false&include_testing_rules=true");
    let req = make_request(RequestMethod::Get, &path, use_staging, false)?;
    parse_response::<StaticAnalysisRulesAPIResponse>(perform_request(req, &path, debug)?)
        .map_err(|e| {
            eprintln!("{e}");
            match e {
                ErrorResponse(404, _) => RulesetNotFound(ruleset_name.to_string()),
                e => e,
            }
        })
        .map(|api_resp| api_resp.into_ruleset())
}

pub fn get_default_rulesets_name_for_language(
    language: String,
    use_staging: bool,
    debug: bool,
) -> Result<Vec<String>> {
    let path = format!("default-rulesets/{}", language);

    let request_builder = make_request(RequestMethod::Get, &path, use_staging, false)?
        .header(HEADER_CONTENT_TYPE, HEADER_CONTENT_TYPE_APPLICATION_JSON);

    parse_response(perform_request(request_builder, &path, debug)?)
        .inspect_err(|e| {
            eprintln!(
                "Error when getting the default rulesets for language {} {:?}",
                language, e
            )
        })
        .map(|d: ApiResponseDefaultRuleset| d.data.attributes.rulesets)
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
    parse_response(perform_request(req, path, debug)?)
        .inspect_err(|e| eprintln!("Error when issuing the diff-aware request {:?}", e))
        .map(|d: DiffAwareResponse| DiffAwareData {
            base_sha: d.data.attributes.base_sha,
            files: d.data.attributes.files,
        })
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
    parse_response(server_response)
        .inspect_err(|e| eprintln!("Error when issuing the config request {:?}", e))
        .map(|d: ConfigResponse| d.data.attributes.config_base64)
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
