// when a rule is not base64
pub const ERROR_DECODING_BASE64: &str = "error-decoding-base64";
// when the code is not base64
pub const ERROR_CODE_NOT_BASE64: &str = "code-not-base64";
// rules and core language are different
pub const ERROR_CODE_LANGUAGE_MISMATCH: &str = "language-mismatch";
// no root node when trying to get the AST
pub const ERROR_CODE_NO_ROOT_NODE: &str = "no-root-node";
pub const ERROR_CHECKSUM_MISMATCH: &str = "checksum-mismatch";

pub const SERVER_HEADER_SHUTDOWN_ENABLED: &str = "X-Static-Analyzer-Server-Shutdown-Enabled";
pub const SERVER_HEADER_KEEPALIVE_ENABLED: &str = "X-Static-Analyzer-Server-Keepalive-Enabled";
pub const SERVER_HEADER_SERVER_VERSION: &str = "X-Static-Analyzer-Server-Version";
pub const SERVER_HEADER_SERVER_REVISION: &str = "X-Static-Analyzer-Server-Revision";
pub const SERVER_HEADER_SERVER_EXPECTED_VERSION: &str = "X-Static-Analyzer-Server-Expected-Version";
