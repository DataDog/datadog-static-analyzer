#![allow(clippy::module_name_repetitions)]

mod configuration_file;
use rocket::Route;

pub fn ide_routes() -> Vec<Route> {
    rocket::routes![
        configuration_file::endpoints::post_ignore_rule,
        configuration_file::endpoints::get_can_onboard,
        configuration_file::endpoints::post_can_onboard_v2,
        configuration_file::endpoints::get_get_rulesets,
        configuration_file::endpoints::post_get_rulesets_v2,
        configuration_file::endpoints::post_add_rulesets,
        configuration_file::endpoints::post_add_rulesets_v2,
    ]
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use openssl::base64;
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

    #[test]
    fn post_ignore_rule() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");
        let config = base64::encode_block(NORMAL_CONFIGURATION.as_bytes());

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
        let config = base64::encode_block(NORMAL_CONFIGURATION.as_bytes());

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
        let config = base64::encode_block(PARSE_ERROR_CONFIGURATION.as_bytes());

        let uri = uri!(super::configuration_file::endpoints::get_can_onboard(
            PathBuf::from(config)
        ));

        let response = client.get(uri).dispatch();

        assert_eq!(response.status(), Status::InternalServerError);
        assert!(response.into_string().contains("Error parsing yaml file"));
    }

    #[test]
    fn get_can_onboard_v1_returns_false() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");
        let config = base64::encode_block(FALSY_CONFIGURATION.as_bytes());

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
        let config = base64::encode_block(WITH_SLASH_CONFIGURATION.as_bytes());

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
        let config = base64::encode_block(NORMAL_CONFIGURATION.as_bytes());

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
        let config = base64::encode_block(PARSE_ERROR_CONFIGURATION.as_bytes());

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
        let config = base64::encode_block(FALSY_CONFIGURATION.as_bytes());

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
        let config = base64::encode_block(NORMAL_CONFIGURATION.as_bytes());

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
        let config = base64::encode_block(WITH_SLASH_CONFIGURATION.as_bytes());

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
        let config = base64::encode_block(NORMAL_CONFIGURATION.as_bytes());

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

    #[test]
    fn add_rulesets_v1() {
        let client = Client::tracked(mount_rocket()).expect("valid rocket instance");
        let config = base64::encode_block(NORMAL_CONFIGURATION.as_bytes());

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
        let config = base64::encode_block(NORMAL_CONFIGURATION.as_bytes());

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
}
