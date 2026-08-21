use crate::constants::{CS_CONFIG_FILE_WITHOUT_EXTENSION, LEGACY_CONFIG_FILE_WITHOUT_EXTENSION};
use crate::datadog_utils::DatadogApiError::InvalidPermission;
use crate::datadog_utils::{
    get_remote_configuration, print_permission_warning, should_use_datadog_backend,
};
use crate::git_utils::get_repository_url;
use anyhow::Context;
use common::model::config_method::ConfigMethod;
use kernel::config::common::ConfigError;
use kernel::config::{file_legacy, file_v1};
use kernel::utils::decode_base64_string;
use secrets::config::common::ConfigError as SecretsConfigError;
use secrets::config::file_v1 as secrets_file_v1;
use std::path::Path;

/// Returns the contents of the configuration file with the given base name.
fn read_config_file(base_path: &Path, base_name: &str) -> anyhow::Result<Option<String>> {
    const EXTENSIONS: [&str; 2] = ["yaml", "yml"];

    for ext in EXTENSIONS {
        let config_path = base_path.join(format!("{base_name}.{ext}"));
        match std::fs::read_to_string(config_path) {
            Ok(contents) => return Ok(Some(contents)),
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    continue;
                }
                return Err(err).context("error when reading the configuration file");
            }
        }
    }
    Ok(None)
}

/// Which schema a configuration text is parsed against. Determined by the file it was read from,
/// not by the document's own contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFileSchema {
    /// A `code-security.datadog.yaml` file, or a configuration served by the backend.
    CodeSecurity,
    /// A `static-analysis.datadog.yaml` file.
    Legacy,
}

/// Reads the local configuration file, without parsing it: the Code Security file takes
/// precedence over the legacy one, and an empty file is ignored. The schema is reported alongside
/// the contents so callers parse against the schema the matched file declares.
fn get_local_config(base_path: &Path) -> anyhow::Result<Option<(String, ConfigFileSchema)>> {
    for (base_name, schema) in [
        (
            CS_CONFIG_FILE_WITHOUT_EXTENSION,
            ConfigFileSchema::CodeSecurity,
        ),
        (
            LEGACY_CONFIG_FILE_WITHOUT_EXTENSION,
            ConfigFileSchema::Legacy,
        ),
    ] {
        if let Some(contents) = read_config_file(base_path, base_name)? {
            if contents.chars().any(|c| !c.is_whitespace()) {
                return Ok(Some((contents, schema)));
            }
        }
    }
    Ok(None)
}

/// Reads SAST's own `sast` section out of a configuration text, parsed against `schema`.
/// Returns `None` when the configuration has no section for SAST.
pub fn parse_sast_config(
    config_contents: &str,
    schema: ConfigFileSchema,
) -> Result<Option<file_v1::SastConfig>, ConfigError> {
    let yaml: file_v1::YamlConfigFile = match schema {
        ConfigFileSchema::CodeSecurity => {
            file_v1::parse_yaml(config_contents).map_err(|err| match err {
                file_v1::ParseError::Parse(inner) => ConfigError::Parse(inner),
                file_v1::ParseError::WrongSchema(version) => {
                    ConfigError::UnsupportedSchema(version.to_string())
                }
            })?
        }
        ConfigFileSchema::Legacy => {
            file_v1::YamlConfigFile::from(file_legacy::parse_yaml(config_contents)?)
        }
    };
    let config: file_v1::ConfigFile = yaml.into();
    Ok(config.sast().cloned())
}

/// Reads Secrets' own `secrets` section out of a configuration text, parsed against `schema`.
/// Returns `None` when the configuration has no section for Secrets.
pub fn parse_secrets_config(
    config_contents: &str,
    schema: ConfigFileSchema,
) -> Result<Option<secrets_file_v1::SecretsConfig>, SecretsConfigError> {
    let yaml: secrets_file_v1::YamlConfigFile = match schema {
        ConfigFileSchema::CodeSecurity => {
            secrets_file_v1::parse_yaml(config_contents).map_err(|err| match err {
                secrets_file_v1::ParseError::Parse(inner) => SecretsConfigError::Parse(inner),
                secrets_file_v1::ParseError::WrongSchema(version) => {
                    SecretsConfigError::UnsupportedSchema(version.to_string())
                }
            })?
        }
        // The legacy schema didn’t have a `secrets` section.
        ConfigFileSchema::Legacy => return Ok(None),
    };
    let config: secrets_file_v1::ConfigFile = yaml.into();
    Ok(config.secrets().cloned())
}

/// Get the final configuration for the analyzer
/// First, try to get the configuration from the file
/// - If the user is a Datadog user (e.g. with API keys), we fetch the remote configuration
///   and merge it
/// - If not, we just return the configuration
///
/// Returns the configuration text and the schema to parse it against, unparsed: every product
/// parses its own section itself, and only when it is enabled. An invalid section for a product
/// that isn't running therefore cannot fail the run, since nothing ever reads it.
pub fn get_config(
    path: &Path,
    debug: bool,
) -> anyhow::Result<Option<(String, ConfigFileSchema, ConfigMethod)>> {
    let local_config = get_local_config(path)?;
    let as_file =
        |(contents, schema): (String, ConfigFileSchema)| (contents, schema, ConfigMethod::File);

    if !should_use_datadog_backend() {
        if debug {
            eprintln!("not attempting to use remote configuration");
        }
        return Ok(local_config.map(as_file));
    }

    let Ok(repository_url) = get_repository_url(path) else {
        if debug {
            eprintln!("no git remote found. not attempting to use remote configuration");
        }
        return Ok(local_config.map(as_file));
    };

    let local_contents = local_config.as_ref().map(|(contents, _)| contents.clone());
    let res = get_remote_configuration(repository_url, local_contents, debug).inspect_err(|err| {
        if matches!(err, InvalidPermission) {
            print_permission_warning("GET_CONFIG");
        } else if debug {
            eprintln!("Error when attempting to fetch the remote config: {err:?}");
            eprintln!("Falling back to the local configuration, if any");
        }
    });
    let Ok(remote_config_base64) = res else {
        return Ok(local_config.map(as_file));
    };

    if debug {
        eprintln!("Remote config (base64): {:?}", remote_config_base64);
    }
    let text = decode_base64_string(remote_config_base64)
        .context("error when decoding base64 remote config")?;

    if let Err(err) = serde_yaml::from_str::<serde_yaml::Value>(&text) {
        if debug {
            eprintln!("Error when parsing remote config: {err:?}");
            eprintln!("Proceeding with local config");
        }
        return Ok(local_config.map(as_file));
    }

    let config_method = if local_config.is_some() {
        ConfigMethod::RemoteConfigurationWithFile
    } else {
        ConfigMethod::RemoteConfiguration
    };
    // The backend always serves the Code Security schema, whatever the local file used.
    Ok(Some((text, ConfigFileSchema::CodeSecurity, config_method)))
}

#[cfg(test)]
mod tests {
    use crate::config_file::{
        get_local_config, parse_sast_config, parse_secrets_config, ConfigFileSchema,
    };
    use crate::constants::{
        CS_CONFIG_FILE_WITHOUT_EXTENSION, LEGACY_CONFIG_FILE_WITHOUT_EXTENSION,
    };
    use std::fs;
    use tempfile::TempDir;

    fn explicit_rulesets(config_contents: &str, schema: ConfigFileSchema) -> Vec<String> {
        parse_sast_config(config_contents, schema)
            .expect("SAST configuration should parse")
            .expect("configuration should have a `sast` section")
            .explicit_rulesets()
            .map(str::to_string)
            .collect()
    }

    const EXTENSIONS: [&str; 2] = ["yaml", "yml"];

    // language=yaml
    const LEGACY: &str = "\
rulesets:
  - java-best-practices
";
    // language=yaml
    const V1: &str = "\
schema-version: v1.0
sast:
  use-rulesets:
    - go-security
";

    #[test]
    fn config_file_legacy() {
        for ext in EXTENSIONS {
            let test_dir = TempDir::new().unwrap();

            let cfg = get_local_config(test_dir.path()).unwrap();
            assert!(cfg.is_none());

            let file_path = test_dir
                .path()
                .join(format!("{LEGACY_CONFIG_FILE_WITHOUT_EXTENSION}.{ext}"));
            fs::write(&file_path, LEGACY).unwrap();

            let (contents, schema) = get_local_config(test_dir.path()).unwrap().unwrap();
            assert_eq!(contents, LEGACY);
            assert_eq!(schema, ConfigFileSchema::Legacy);
            assert_eq!(
                explicit_rulesets(&contents, schema),
                &["java-best-practices"]
            );
            // The legacy schema has no `secrets` section.
            assert!(parse_secrets_config(&contents, schema).unwrap().is_none());
        }
    }

    #[test]
    fn config_file_v1() {
        for ext in EXTENSIONS {
            let test_dir = TempDir::new().unwrap();

            let cfg = get_local_config(test_dir.path()).unwrap();
            assert!(cfg.is_none());

            let file_path = test_dir
                .path()
                .join(format!("{CS_CONFIG_FILE_WITHOUT_EXTENSION}.{ext}"));
            fs::write(&file_path, V1).unwrap();

            let (contents, schema) = get_local_config(test_dir.path()).unwrap().unwrap();
            assert_eq!(contents, V1);
            assert_eq!(schema, ConfigFileSchema::CodeSecurity);
            assert_eq!(explicit_rulesets(&contents, schema), &["go-security"]);
        }
    }

    /// Code Security config, if present, is used before a legacy config.
    #[test]
    fn config_file_precedence() {
        let test_dir = TempDir::new().unwrap();
        for (content, prefix) in [
            (LEGACY, LEGACY_CONFIG_FILE_WITHOUT_EXTENSION),
            (V1, CS_CONFIG_FILE_WITHOUT_EXTENSION),
        ] {
            let file_path = test_dir.path().join(format!("{prefix}.yaml"));
            fs::write(&file_path, content).unwrap();
        }
        let (contents, schema) = get_local_config(test_dir.path()).unwrap().unwrap();

        assert_eq!(contents, V1);
        assert_eq!(schema, ConfigFileSchema::CodeSecurity);
    }

    /// An empty configuration file is ignored.
    #[test]
    fn empty_config_file() {
        for prefix in [
            LEGACY_CONFIG_FILE_WITHOUT_EXTENSION,
            CS_CONFIG_FILE_WITHOUT_EXTENSION,
        ] {
            for content in ["", "\n  \t \r\n "] {
                let test_dir = TempDir::new().unwrap();
                let file_path = test_dir.path().join(format!("{prefix}.yaml"));
                fs::write(&file_path, content).unwrap();
                assert!(get_local_config(test_dir.path()).unwrap().is_none());
            }
        }
    }
}
