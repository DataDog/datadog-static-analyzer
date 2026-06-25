#![allow(clippy::module_name_repetitions)]

mod configuration_file;
mod secrets;
use rocket::Route;

#[allow(deprecated)]
pub fn ide_routes() -> Vec<Route> {
    rocket::routes![
        configuration_file::endpoints::post_ignore_rule,
        configuration_file::endpoints::get_can_onboard,
        configuration_file::endpoints::post_can_onboard_v2,
        configuration_file::endpoints::get_get_rulesets,
        configuration_file::endpoints::post_get_rulesets_v2,
        configuration_file::endpoints::post_parse_config,
        configuration_file::endpoints::post_add_rulesets,
        configuration_file::endpoints::post_add_rulesets_v2,
        secrets::endpoints::post_scan_secrets,
    ]
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use kernel::utils::encode_base64_string;
    use rocket::{
        form::validate::Contains,
        http::{ContentType, Status},
        local::blocking::Client,
        uri, Rocket,
    };

    use crate::datadog_static_analyzer_server::ide::ide_routes;

    fn mount_rocket() -> Rocket<rocket::Build> {
        rocket::build().mount("/", ide_routes())
    }

    const NORMAL_CONFIGURATION: &'static str = r#"schema-version: v1
rulesets:
- java-1
- java-security"#;

    const PARSE_ERROR_CONFIGURATION: &'static str = r#"schema-version: v50000
rulesets:
- java-1
- java-security
only:
- ignore/domain"#;

    const FALSY_CONFIGURATION: &'static str = r#"schema-version: v1
rulesets:
- java-1
- java-security
only:
- ignore/domain"#;

    const WITH_SLASH_CONFIGURATION: &'static str = r#"schema-version: v1
rulesets:
- java-1-??
- java-security"#;

    const UNIFIED_CONFIGURATION: &'static str = r#"schema-version: v1.0
sast:
  use-rulesets:
    - python-security
    - java-security
"#;

    const UNIFIED_CONFIGURATION_NO_RULESETS: &'static str = "schema-version: v1.0\n";

    #[test]
    fn post_ignore_rule() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");
        let config = encode_base64_string(NORMAL_CONFIGURATION.to_string());

        let response = client
            .post(uri!(super::configuration_file::endpoints::post_ignore_rule))
            .header(ContentType::JSON)
            .body(format!(
                r#"{{ 
                "rule": "ruleset1/rule1",
                "configuration": "{config}", 
                "encoded": false 
            }}"#
            ))
            .dispatch();

        let expected = r#"schema-version: v1
rulesets:
  - java-1
  - java-security
  - ruleset1:
    rules:
      rule1:
        ignore:
          - "**"
"#;

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_string().unwrap(), expected);
    }

    #[test]
    fn get_can_onboard_v1() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");
        let config = encode_base64_string(NORMAL_CONFIGURATION.to_string());

        let uri = uri!(super::configuration_file::endpoints::get_can_onboard(
            PathBuf::from(config)
        ));

        let response = client.get(uri).dispatch();

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_string().unwrap(), "true");
    }

    #[test]
    fn get_can_onboard_v1_returns_parse_error() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");
        let config = encode_base64_string(PARSE_ERROR_CONFIGURATION.to_string());

        let uri = uri!(super::configuration_file::endpoints::get_can_onboard(
            PathBuf::from(config)
        ));

        let response = client.get(uri).dispatch();

        assert_eq!(response.status(), Status::BadRequest);
        assert!(response.into_string().contains("Error parsing yaml file"));
    }

    #[test]
    fn get_can_onboard_v1_returns_false() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");
        let config = encode_base64_string(FALSY_CONFIGURATION.to_string());

        let uri = uri!(super::configuration_file::endpoints::get_can_onboard(
            PathBuf::from(config)
        ));

        let response = client.get(uri).dispatch();

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_string().unwrap(), "false");
    }

    #[test]
    fn get_can_onboard_v1_does_not_fail_because_of_slash_in_content() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");
        let config = encode_base64_string(WITH_SLASH_CONFIGURATION.to_string());

        assert!(config.contains("/"), "{}", config);

        let uri = uri!(super::configuration_file::endpoints::get_can_onboard(
            PathBuf::from(config)
        ));

        let response = client.get(uri).dispatch();

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_string().unwrap(), "true");
    }

    #[test]
    fn get_can_onboard_v2() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");
        let config = encode_base64_string(NORMAL_CONFIGURATION.to_string());

        let response = client
            .post(uri!(
                super::configuration_file::endpoints::post_can_onboard_v2
            ))
            .header(ContentType::JSON)
            .body(format!(
                r#"{{ 
                "configuration": "{config}"
            }}"#
            ))
            .dispatch();

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_string().unwrap(), "true");
    }

    #[test]
    fn get_can_onboard_v2_returns_parse_error() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");
        let config = encode_base64_string(PARSE_ERROR_CONFIGURATION.to_string());

        let response = client
            .post(uri!(
                super::configuration_file::endpoints::post_can_onboard_v2
            ))
            .header(ContentType::JSON)
            .body(format!(
                r#"{{ 
                "configuration": "{config}"
            }}"#
            ))
            .dispatch();

        assert_eq!(response.status(), Status::InternalServerError);
        assert!(response.into_string().contains("Error parsing yaml file"));
    }

    #[test]
    fn get_can_onboard_v2_returns_false() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");
        let config = encode_base64_string(FALSY_CONFIGURATION.to_string());

        let response = client
            .post(uri!(
                super::configuration_file::endpoints::post_can_onboard_v2
            ))
            .header(ContentType::JSON)
            .body(format!(
                r#"{{ 
                "configuration": "{config}"
            }}"#
            ))
            .dispatch();

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_string().unwrap(), "false");
    }

    #[test]
    fn get_rulesets_v1() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");
        let config = encode_base64_string(NORMAL_CONFIGURATION.to_string());

        let uri = uri!(super::configuration_file::endpoints::get_get_rulesets(
            PathBuf::from(config)
        ));

        let response = client.get(uri).dispatch();

        let expected = r#"["java-1","java-security"]"#;

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_string().unwrap(), expected);
    }

    #[test]
    fn get_rulesets_v1_does_not_fail_because_of_slash_in_content() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");
        let config = encode_base64_string(WITH_SLASH_CONFIGURATION.to_string());

        assert!(config.contains("/"));

        let uri = uri!(super::configuration_file::endpoints::get_get_rulesets(
            PathBuf::from(config)
        ));

        let response = client.get(uri).dispatch();

        let expected = r#"["java-1-??","java-security"]"#;

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_string().unwrap(), expected);
    }

    #[test]
    fn get_rulesets_v2() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");
        let config = encode_base64_string(NORMAL_CONFIGURATION.to_string());

        let response = client
            .post(uri!(
                super::configuration_file::endpoints::post_get_rulesets_v2
            ))
            .header(ContentType::JSON)
            .body(format!(
                r#"{{
                "configuration": "{config}"
            }}"#
            ))
            .dispatch();

        let expected = r#"["java-1","java-security"]"#;

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_string().unwrap(), expected);
    }

    /// Legacy contract: the deprecated v1 route must return `[]` with HTTP 200
    /// on an unparseable config instead of surfacing a 500. Older IDE clients
    /// rely on this best-effort behavior.
    #[test]
    fn get_rulesets_v1_returns_empty_on_parse_error() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");
        let config = encode_base64_string(PARSE_ERROR_CONFIGURATION.to_string());

        let uri = uri!(super::configuration_file::endpoints::get_get_rulesets(
            PathBuf::from(config)
        ));

        let response = client.get(uri).dispatch();

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_string().unwrap(), "[]");
    }

    /// Legacy contract: the deprecated v2 route must return `[]` with HTTP 200
    /// on an unparseable config instead of surfacing a 500. Older IDE clients
    /// rely on this best-effort behavior.
    #[test]
    fn get_rulesets_v2_returns_empty_on_parse_error() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");
        let config = encode_base64_string(PARSE_ERROR_CONFIGURATION.to_string());

        let response = client
            .post(uri!(
                super::configuration_file::endpoints::post_get_rulesets_v2
            ))
            .header(ContentType::JSON)
            .body(format!(
                r#"{{
                "configuration": "{config}"
            }}"#
            ))
            .dispatch();

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_string().unwrap(), "[]");
    }

    #[test]
    fn parse_config_returns_sast_rulesets() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");

        let response = client
            .post(uri!(
                super::configuration_file::endpoints::post_parse_config
            ))
            .header(ContentType::JSON)
            .body(
                serde_json::json!({
                    "configuration": NORMAL_CONFIGURATION,
                })
                .to_string(),
            )
            .dispatch();

        let expected = r#"{"sast":{"rulesets":["java-1","java-security"]}}"#;

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_string().unwrap(), expected);
    }

    #[test]
    fn parse_config_returns_error_on_parse_failure() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");

        let response = client
            .post(uri!(
                super::configuration_file::endpoints::post_parse_config
            ))
            .header(ContentType::JSON)
            .body(
                serde_json::json!({
                    "configuration": PARSE_ERROR_CONFIGURATION,
                })
                .to_string(),
            )
            .dispatch();

        assert_eq!(response.status(), Status::BadRequest);
        assert!(response.into_string().contains("Error parsing yaml file"));
    }

    #[test]
    fn add_rulesets_v1() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");
        let config = encode_base64_string(NORMAL_CONFIGURATION.to_string());

        let response = client
            .post(uri!(
                super::configuration_file::endpoints::post_add_rulesets
            ))
            .header(ContentType::JSON)
            .body(format!(
                r#"{{ 
                "rulesets": ["ruleset1", "ruleset2"],
                "configuration": "{config}",
                "encoded": false
            }}"#
            ))
            .dispatch();

        let expected = r#"schema-version: v1
rulesets:
  - java-1
  - java-security
  - ruleset1
  - ruleset2
"#;

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_string().unwrap(), expected);
    }

    #[test]
    fn add_rulesets_v2() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");
        let config = encode_base64_string(NORMAL_CONFIGURATION.to_string());

        let response = client
            .post(uri!(
                super::configuration_file::endpoints::post_add_rulesets_v2
            ))
            .header(ContentType::JSON)
            .body(format!(
                r#"{{
                "rulesets": ["ruleset1", "ruleset2"],
                "configuration": "{config}",
                "encoded": false
            }}"#
            ))
            .dispatch();

        let expected = r#"schema-version: v1
rulesets:
  - java-1
  - java-security
  - ruleset1
  - ruleset2
"#;

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_string().unwrap(), expected);
    }

    // --- schema_version strict validation ---

    #[test]
    fn parse_config_accepts_unified_content_with_v1_schema_version() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");

        let response = client
            .post(uri!(
                super::configuration_file::endpoints::post_parse_config
            ))
            .header(ContentType::JSON)
            .body(
                serde_json::json!({
                    "configuration": UNIFIED_CONFIGURATION,
                    "schema_version": "v1",
                })
                .to_string(),
            )
            .dispatch();

        assert_eq!(response.status(), Status::Ok);
        let body = response.into_string().unwrap();
        assert!(body.contains("python-security"));
        assert!(body.contains("java-security"));
    }

    #[test]
    fn parse_config_rejects_legacy_content_declared_as_unified() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");

        let response = client
            .post(uri!(
                super::configuration_file::endpoints::post_parse_config
            ))
            .header(ContentType::JSON)
            .body(
                serde_json::json!({
                    "configuration": NORMAL_CONFIGURATION,
                    "schema_version": "v1",
                })
                .to_string(),
            )
            .dispatch();

        assert_eq!(response.status(), Status::UnprocessableEntity);
        assert!(response
            .into_string()
            .unwrap()
            .contains("does not match the declared schema version"));
    }

    #[test]
    fn parse_config_rejects_unified_content_with_no_schema_version() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");

        let response = client
            .post(uri!(
                super::configuration_file::endpoints::post_parse_config
            ))
            .header(ContentType::JSON)
            .body(
                serde_json::json!({
                    "configuration": UNIFIED_CONFIGURATION,
                })
                .to_string(),
            )
            .dispatch();

        // absent schema_version defaults to LEGACY; unified content is a mismatch
        assert_eq!(response.status(), Status::UnprocessableEntity);
    }

    /// Backward compat: old extensions send legacy content without schema_version — must work.
    #[test]
    fn parse_config_backward_compat_legacy_content_no_schema_version() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");

        let response = client
            .post(uri!(
                super::configuration_file::endpoints::post_parse_config
            ))
            .header(ContentType::JSON)
            .body(
                serde_json::json!({
                    "configuration": NORMAL_CONFIGURATION,
                })
                .to_string(),
            )
            .dispatch();

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.into_string().unwrap(),
            r#"{"sast":{"rulesets":["java-1","java-security"]}}"#
        );
    }

    #[test]
    fn ignore_rule_rejects_schema_version_mismatch() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");
        let config = encode_base64_string(NORMAL_CONFIGURATION.to_string());

        let response = client
            .post(uri!(super::configuration_file::endpoints::post_ignore_rule))
            .header(ContentType::JSON)
            .body(format!(
                r#"{{
                "rule": "ruleset1/rule1",
                "configuration": "{config}",
                "encoded": false,
                "schema_version": "v1"
            }}"#
            ))
            .dispatch();

        assert_eq!(response.status(), Status::UnprocessableEntity);
    }

    #[test]
    fn can_onboard_v2_rejects_schema_version_mismatch() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");
        let config = encode_base64_string(NORMAL_CONFIGURATION.to_string());

        let response = client
            .post(uri!(
                super::configuration_file::endpoints::post_can_onboard_v2
            ))
            .header(ContentType::JSON)
            .body(format!(
                r#"{{
                "configuration": "{config}",
                "schema_version": "v1"
            }}"#
            ))
            .dispatch();

        assert_eq!(response.status(), Status::UnprocessableEntity);
    }

    #[test]
    fn add_rulesets_creates_unified_file_when_schema_version_v1() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");

        let response = client
            .post(uri!(
                super::configuration_file::endpoints::post_add_rulesets_v2
            ))
            .header(ContentType::JSON)
            .body(
                serde_json::json!({
                    "rulesets": ["python-security"],
                    "encoded": false,
                    "schema_version": "v1",
                })
                .to_string(),
            )
            .dispatch();

        assert_eq!(response.status(), Status::Ok);
        let body = response.into_string().unwrap();
        // unified format uses schema-version: v1.0
        assert!(body.contains("schema-version: v1.0"), "body: {body}");
        assert!(body.contains("python-security"), "body: {body}");
    }

    #[test]
    fn can_onboard_v2_accepts_unified_content_with_v1_schema_version() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");
        let config = encode_base64_string(UNIFIED_CONFIGURATION_NO_RULESETS.to_string());

        let response = client
            .post(uri!(
                super::configuration_file::endpoints::post_can_onboard_v2
            ))
            .header(ContentType::JSON)
            .body(format!(
                r#"{{
                "configuration": "{config}",
                "schema_version": "v1"
            }}"#
            ))
            .dispatch();

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_string().unwrap(), "true");
    }
}
