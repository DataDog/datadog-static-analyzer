use crate::constants::DATADOG_CONFIG_FILE_WITHOUT_EXTENSION;
use crate::datadog_utils::DatadogApiError::InvalidPermission;
use crate::datadog_utils::{
    get_remote_configuration, print_permission_warning, should_use_datadog_backend,
};
use crate::git_utils::get_repository_url;
use anyhow::{anyhow, Context};
use kernel::config::common::ConfigMethod;
use kernel::config::file_v1;
use kernel::config::file_v1::parse_config_file;
use kernel::utils::{decode_base64_string, encode_base64_string};
use std::path::Path;

// We first try to read static-analysis.datadog.yml
// If it fails, we try to read static-analysis.datadog.yaml
// If the file does not exist, we return a Ok(None).
// If there is an error reading the file, we return a failure
pub fn read_config_file(base_path: &str) -> anyhow::Result<Option<String>> {
    const EXTENSIONS: [&str; 2] = ["yml", "yaml"];

    for ext in EXTENSIONS {
        let config_path =
            Path::new(base_path).join(format!("{DATADOG_CONFIG_FILE_WITHOUT_EXTENSION}.{ext}"));
        match std::fs::read_to_string(config_path) {
            Ok(contents) => {
                return if !contents.is_empty() {
                    Ok(Some(contents))
                } else {
                    Err(anyhow!("the config file is empty"))
                }
            }
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

/// Get the final configuration for the analyzer
/// First, try to get the configuration from the file
/// - If the user is a Datadog user (e.g. with API keys), we fetch the remote configuration
///   and merge it
/// - If not, we just return the configuration
pub fn get_config(
    path: &str,
    debug: bool,
) -> anyhow::Result<Option<(file_v1::ConfigFile, ConfigMethod)>> {
    let local_file_contents = read_config_file(path)?;
    let local_config = local_file_contents
        .as_ref()
        .map(|c| parse_config_file(c))
        .transpose()?;

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

    let res = get_remote_configuration(
        repository_url,
        local_file_contents.map(encode_base64_string),
        debug,
    )
    .inspect_err(|err| {
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

    let res = parse_config_file(&text).inspect_err(|err| {
        if debug {
            eprintln!("Error when parsing remote config: {err:?}");
            eprintln!("Proceeding with local config");
        }
    });
    let Ok(remote_config) = res else {
        return Ok(local_config.map(|c| (c, ConfigMethod::File)));
    };

    let config_method = if local_config.is_some() {
        ConfigMethod::RemoteConfigurationWithFile
    } else {
        ConfigMethod::RemoteConfiguration
    };
    Ok(Some((remote_config, config_method)))
}
