pub static DATADOG_CONFIG_FILE_WITHOUT_PREFIX: &str = "static-analysis.datadog";

pub static DATADOG_HEADER_APP_KEY: &str = "dd-application-key";
pub static DATADOG_HEADER_API_KEY: &str = "dd-api-key";
pub static DATADOG_HEADER_JWT_TOKEN: &str = "dd-auth-jwt";
pub static HEADER_CONTENT_TYPE: &str = "Content-Type";
pub static HEADER_CONTENT_TYPE_APPLICATION_JSON: &str = "application/json";
pub static SARIF_PROPERTY_DATADOG_FINGERPRINT: &str = "DATADOG_FINGERPRINT";
pub static SARIF_PROPERTY_SHA: &str = "SHA";
pub static DEFAULT_MAX_CPUS: usize = 8;
pub static DEFAULT_MAX_FILE_SIZE_KB: u64 = 200;
// See https://docs.gitlab.com/ee/ci/variables/predefined_variables.html
pub static GITLAB_ENVIRONMENT_VARIABLE_COMMIT_BRANCH: &str = "CI_COMMIT_BRANCH";
pub static GIT_HEAD: &str = "HEAD";
pub static EXIT_CODE_INVALID_CONFIGURATION: i32 = 11;
pub static EXIT_CODE_FAIL_ON_VIOLATION: i32 = 12;
pub static EXIT_CODE_NO_OUTPUT: i32 = 13;
pub static EXIT_CODE_NO_DIRECTORY: i32 = 14;
pub static EXIT_CODE_INVALID_DIRECTORY: i32 = 15;
pub static EXIT_CODE_UNSAFE_SUBDIRECTORIES: i32 = 16;
pub static EXIT_CODE_RULE_FILE_WITH_CONFIGURATION: i32 = 17;
pub static EXIT_CODE_RULE_CHECKSUM_INVALID: i32 = 18;
pub static EXIT_CODE_NO_SECRET_OR_STATIC_ANALYSIS: i32 = 19;
pub static EXIT_CODE_SHA_OR_DEFAULT_BRANCH: i32 = 20;
pub static EXIT_CODE_GITHOOK_FAILED: i32 = 42;
