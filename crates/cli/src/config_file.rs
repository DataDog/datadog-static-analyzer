use crate::constants;
use crate::datadog_utils::{get_remote_configuration, should_use_datadog_backend};
use crate::git_utils::get_repository_url;
use anyhow::{anyhow, Context, Result};
use kernel::config_file::parse_config_file;
use kernel::model::config_file::{ConfigFile, ConfigMethod};
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
    let config_file = read_config_file(path);
    let repository_url_opt = get_repository_url(path);

    // Get the config file
    config_file.map(|cf| {
        // if we need to fetch the remote config
        if should_use_datadog_backend() && repository_url_opt.is_ok() {
            let existing_config_file_base64 =
                read_config_file_in_base64(path).expect("cannot get the config file in base64");

            let has_config_file = existing_config_file_base64.is_some();

            let remote_config = get_remote_configuration(
                repository_url_opt.expect("repository URL should exist"),
                existing_config_file_base64,
                debug,
            );

            // if we get the remote config, we parse it. If we succeed, we use the remote config
            // otherwise, we use the file config.
            match remote_config {
                Ok(rc) => {
                    if debug {
                        eprintln!("Remote config (base64): {:?}", rc);
                    }

                    let remote_config_string =
                        decode_base64_string(rc).expect("error when decoding base64");
                    match parse_config_file(remote_config_string.as_str()) {
                        Ok(remote_config) => {
                            let config_method = if has_config_file {
                                ConfigMethod::RemoteConfigurationWithFile
                            } else {
                                ConfigMethod::RemoteConfiguration
                            };
                            Some((remote_config, config_method))
                        }
                        Err(e) => {
                            if debug {
                                eprintln!("Error when parsing remote config: {:?}", e);
                                eprintln!("Proceeding with local config");
                            }

                            cf.map(|c| (c, ConfigMethod::File))
                        }
                    }
                }
                Err(e) => {
                    if debug {
                        eprintln!("Error when attempting to fetch the remote config: {:?}", e);
                        eprintln!("Falling back to the local configuration, if any")
                    }
                    cf.map(|c| (c, ConfigMethod::File))
                }
            }
        } else {
            if debug {
                eprintln!("not attempting to use remote configuration");
            }
            cf.map(|c| (c, ConfigMethod::File))
        }
    })
}
