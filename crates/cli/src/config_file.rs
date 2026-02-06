use crate::constants;
use crate::datadog_utils::DatadogApiError::InvalidPermission;
use crate::datadog_utils::{
    get_remote_configuration, print_permission_warning, should_use_datadog_backend,
};
use crate::git_utils::get_repository_url;
use anyhow::{anyhow, Context, Result};
use kernel::config::common::{ConfigFile, ConfigMethod};
use kernel::config::file_v1::parse_config_file;
use kernel::utils::{decode_base64_string, encode_base64_string};
use std::fs::File;
use std::io::Read;
use std::path::Path;

fn get_config_file(path: &str) -> Result<Option<File>> {
    let yml_file_path = Path::new(path).join(format!(
        "{}.yml",
        constants::DATADOG_CONFIG_FILE_WITHOUT_PREFIX
    ));
    let yaml_file_path = Path::new(path).join(format!(
        "{}.yaml",
        constants::DATADOG_CONFIG_FILE_WITHOUT_PREFIX
    ));

    // first, static-analysis.datadog.yml
    match File::open(yml_file_path) {
        Ok(f) => Ok(Some(f)),
        Err(e1) if e1.kind() == std::io::ErrorKind::NotFound => {
            // second, static-analysis.datadog.yaml
            match File::open(yaml_file_path) {
                Ok(f) => Ok(Some(f)),
                Err(e2) if e2.kind() == std::io::ErrorKind::NotFound => Ok(None),
                _ => Err(anyhow!("cannot open config file")),
            }
        }
        _ => Err(anyhow!("cannot open config file")),
    }
}

// We first try to read static-analysis.datadog.yml
// If it fails, we try to read static-analysis.datadog.yaml
// If the file does not exist, we return a Ok(None).
// If there is an error reading the file, we return a failure
pub fn read_config_file(path: &str) -> Result<Option<ConfigFile>> {
    if let Some(mut file) = get_config_file(path)? {
        let mut contents = String::new();

        let size_read = file
            .read_to_string(&mut contents)
            .context("error when reading the configration file")?;
        if size_read == 0 {
            return Err(anyhow!("the config file is empty"));
        }
        parse_config_file(&contents).map(Some)
    } else {
        Ok(None)
    }
}

// Read the config file in base64
pub fn read_config_file_in_base64(path: &str) -> Result<Option<String>> {
    if let Some(mut file) = get_config_file(path)? {
        let mut contents = String::new();

        let size_read = file
            .read_to_string(&mut contents)
            .context("error when reading the configration file")?;
        if size_read == 0 {
            return Err(anyhow!("the config file is empty"));
        }
        Ok(Some(encode_base64_string(contents)))
    } else {
        Ok(None)
    }
}

/// Get the final configuration for the analyzer
/// First, try to get the configuration from the file
/// - If the user is a Datadog user (e.g. with API keys), we fetch the remote configuration
///   and merge it
/// - If not, we just return the configuration
pub fn get_config(path: &str, debug: bool) -> Result<Option<(ConfigFile, ConfigMethod)>> {
    let config_file = read_config_file(path)?;

    if !should_use_datadog_backend() {
        if debug {
            eprintln!("not attempting to use remote configuration");
        }
        return Ok(config_file.map(|c| (c, ConfigMethod::File)));
    }

    let Ok(repository_url) = get_repository_url(path) else {
        if debug {
            eprintln!("no git remote found. not attempting to use remote configuration");
        }
        return Ok(config_file.map(|c| (c, ConfigMethod::File)));
    };

    let local_config_base64 = read_config_file_in_base64(path)?;
    let has_local_config = local_config_base64.is_some();

    let res =
        get_remote_configuration(repository_url, local_config_base64, debug).inspect_err(|err| {
            if matches!(err, InvalidPermission) {
                print_permission_warning("GET_CONFIG");
            } else if debug {
                eprintln!("Error when attempting to fetch the remote config: {err:?}");
                eprintln!("Falling back to the local configuration, if any");
            }
        });
    let Ok(remote_config_base64) = res else {
        return Ok(config_file.map(|c| (c, ConfigMethod::File)));
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
        return Ok(config_file.map(|c| (c, ConfigMethod::File)));
    };

    let config_method = if has_local_config {
        ConfigMethod::RemoteConfigurationWithFile
    } else {
        ConfigMethod::RemoteConfiguration
    };
    Ok(Some((remote_config, config_method)))
}
