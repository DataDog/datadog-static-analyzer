pub static DATADOG_CONFIG_FILE_WITHOUT_PREFIX: &str = "static-analysis.datadog";

pub static DATADOG_HEADER_APP_KEY: &str = "dd-application-key";
pub static DATADOG_HEADER_API_KEY: &str = "dd-api-key";
pub static HEADER_CONTENT_TYPE: &str = "Content-Type";
pub static HEADER_CONTENT_TYPE_APPLICATION_JSON: &str = "application/json";
pub static SARIF_PROPERTY_DATADOG_FINGERPRINT: &str = "DATADOG_FINGERPRINT";
pub static SARIF_PROPERTY_SHA: &str = "SHA";

pub static DEFAULT_MAX_FILE_SIZE_KB: u64 = 200;
// See https://docs.gitlab.com/ee/ci/variables/predefined_variables.html
pub static GITLAB_ENVIRONMENT_VARIABLE_COMMIT_BRANCH: &str = "CI_COMMIT_BRANCH";
pub static GIT_HEAD: &str = "HEAD";
