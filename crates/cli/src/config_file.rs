use crate::constants::LEGACY_CONFIG_FILE_WITHOUT_EXTENSION;
use crate::datadog_utils::DatadogApiError::InvalidPermission;
use crate::datadog_utils::{
    get_remote_configuration, print_permission_warning, should_use_datadog_backend,
};
use crate::git_utils::get_repository_url;
use anyhow::{anyhow, Context};
use kernel::config::common::ConfigMethod;
use kernel::config::{file_legacy, file_v1};
use kernel::utils::decode_base64_string;
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

fn get_local_config(base_path: &Path) -> anyhow::Result<Option<(file_v1::ConfigFile, String)>> {
    let mut local_config: Option<(file_v1::ConfigFile, String)> = None;
    if let Some(contents) = read_config_file(base_path, LEGACY_CONFIG_FILE_WITHOUT_EXTENSION)? {
        if contents.trim().is_empty() {
            return Err(anyhow!("the config file is empty"));
        }
        let parsed = file_legacy::parse_yaml(&contents)?;
        let as_v1 = file_v1::YamlConfigFile::from(parsed);
        local_config = Some((as_v1.into(), contents));
    }
    Ok(local_config)
}

/// Get the final configuration for the analyzer
/// First, try to get the configuration from the file
/// - If the user is a Datadog user (e.g. with API keys), we fetch the remote configuration
///   and merge it
/// - If not, we just return the configuration
pub fn get_config(
    path: &Path,
    debug: bool,
) -> anyhow::Result<Option<(file_v1::ConfigFile, ConfigMethod)>> {
    let (local_config, file_contents) =
        get_local_config(path)?.map_or((None, None), |(cfg, contents)| (Some(cfg), Some(contents)));

    if !should_use_datadog_backend() {
        if debug {
            eprintln!("not attempting to use remote configuration");
        }
        return Ok(local_config.map(|c| (c, ConfigMethod::File)));
    }

    let Ok(repository_url) = get_repository_url(path) else {
        if debug {
            eprintln!("no git remote found. not attempting to use remote configuration");
        }
        return Ok(local_config.map(|c| (c, ConfigMethod::File)));
    };

    let res = get_remote_configuration(repository_url, file_contents, debug).inspect_err(|err| {
        if matches!(err, InvalidPermission) {
            print_permission_warning("GET_CONFIG");
        } else if debug {
            eprintln!("Error when attempting to fetch the remote config: {err:?}");
            eprintln!("Falling back to the local configuration, if any");
        }
    });
    let Ok(remote_config_base64) = res else {
        return Ok(local_config.map(|c| (c, ConfigMethod::File)));
    };

    if debug {
        eprintln!("Remote config (base64): {:?}", remote_config_base64);
    }
    let text = decode_base64_string(remote_config_base64)
        .context("error when decoding base64 remote config")?;

    let res = file_v1::parse_yaml(&text).inspect_err(|err| {
        if debug {
            eprintln!("Error when parsing remote config: {err:?}");
            eprintln!("Proceeding with local config");
        }
    });
    let Ok(remote_yaml) = res else {
        return Ok(local_config.map(|c| (c, ConfigMethod::File)));
    };
    let remote_config: file_v1::ConfigFile = remote_yaml.into();

    let config_method = if local_config.is_some() {
        ConfigMethod::RemoteConfigurationWithFile
    } else {
        ConfigMethod::RemoteConfiguration
    };
    Ok(Some((remote_config, config_method)))
}

#[cfg(test)]
mod tests {
    use crate::config_file::get_local_config;
    use crate::constants::LEGACY_CONFIG_FILE_WITHOUT_EXTENSION;
    use std::fs;
    use tempfile::TempDir;

    const EXTENSIONS: [&str; 2] = ["yaml", "yml"];

    // language=yaml
    const LEGACY: &str = "\
rulesets:
  - java-best-practices
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

            let (cfg, contents) = get_local_config(test_dir.path()).unwrap().unwrap();
            assert_eq!(contents, LEGACY);
            assert_eq!(
                cfg.sast().unwrap().explicit_rulesets().collect::<Vec<_>>(),
                &["java-best-practices"]
            );
        }
    }
}
