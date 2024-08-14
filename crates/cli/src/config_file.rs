use crate::constants;
use crate::datadog_utils::{get_remote_configuration, should_use_datadog_backend};
use crate::git_utils::get_repository_url;
use anyhow::{anyhow, Context, Result};
use kernel::config_file::parse_config_file;
use kernel::model::config_file::ConfigFile;
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
    match get_config_file(path) {
        Ok(file_opt) => {
            if let Some(mut file) = file_opt {
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
        Err(e) => Err(e),
    }
}

// Read the config file in base64
pub fn read_config_file_in_base64(path: &str) -> Result<Option<String>> {
    match get_config_file(path) {
        Ok(file_opt) => {
            if let Some(mut file) = file_opt {
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
        Err(e) => Err(e),
    }
}

/// Get the final configuration for the analyzer
/// First, try to get the configuration from the file
/// - If the user is a Datadog user (e.g. with API keys), we fetch the remote configuration
///   and merge it
/// - If not, we just return the configuration
pub fn get_config(path: &str, debug: bool) -> Result<Option<ConfigFile>> {
    let config_file = read_config_file(path);
    let repository_url_opt = get_repository_url(path);

    config_file.map(|cf| {
        if should_use_datadog_backend() && repository_url_opt.is_ok() {
            let existing_config_file_base64 =
                read_config_file_in_base64(path).expect("cannot get the config file in base64");
            let remote_config = get_remote_configuration(
                repository_url_opt.expect("repository URL should exist"),
                existing_config_file_base64,
                debug,
            );

            match remote_config {
                Ok(rc) => {
                    if debug {
                        eprintln!("Remote config (base64): {:?}", rc);
                    }

                    let remote_config_base64 =
                        decode_base64_string(rc).expect("error when decoding base64");
                    match parse_config_file(remote_config_base64.as_str()) {
                        Ok(remote_config) => Some(remote_config),
                        Err(e) => {
                            eprintln!("Error when parsing remote config: {:?}", e);
                            eprintln!("Proceeding with local config");
                            cf
                        }
                    }
                }
                Err(e) => {
                    if debug {
                        eprintln!("Error when attempting to fetch the remote config: {:?}", e);
                        eprintln!("Falling back to the local configuration, if any")
                    }
                    cf
                }
            }
        } else {
            if debug {
                eprintln!("not attempting to use remote configuration");
            }
            cf
        }
    })
}
