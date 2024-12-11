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

// application error: greater or equal to 10 and less than 50
pub static EXIT_CODE_FAIL_ON_VIOLATION: i32 = 10;
pub static EXIT_CODE_GITHOOK_FAILED: i32 = 11;
pub static EXIT_CODE_RULE_CHECKSUM_INVALID: i32 = 12;

// user errors, all more than 50
pub static EXIT_CODE_INVALID_CONFIGURATION: i32 = 50;
pub static EXIT_CODE_SHA_OR_DEFAULT_BRANCH: i32 = 51;
pub static EXIT_CODE_NO_SECRET_OR_STATIC_ANALYSIS: i32 = 52;
pub static EXIT_CODE_RULE_FILE_WITH_CONFIGURATION: i32 = 53;
pub static EXIT_CODE_NO_OUTPUT: i32 = 54;
pub static EXIT_CODE_NO_DIRECTORY: i32 = 55;
pub static EXIT_CODE_INVALID_DIRECTORY: i32 = 56;
pub static EXIT_CODE_UNSAFE_SUBDIRECTORIES: i32 = 57;
