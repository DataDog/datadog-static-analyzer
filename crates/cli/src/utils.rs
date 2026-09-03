use crate::constants::DEFAULT_MAX_CPUS;
use crate::model::run_configuration::RunConfiguration;
use crate::model::sast_configuration::SastConfiguration;
use crate::model::secrets_configuration::SecretsConfiguration;
use crate::rule_utils::get_languages_for_rules;
use common::model::config_method::ConfigMethod;
use kernel::constants::{CARGO_VERSION, VERSION};
use kernel::model::common::OutputFormat;

/// Returns the user's requested core count, clamped to the number of logical cores on the system.
/// If unspecified, up to [DEFAULT_MAX_CPUS] CPUs will be used.
pub fn choose_cpu_count(user_input: Option<usize>) -> usize {
    let logical_cores = num_cpus::get();
    let cores = user_input.unwrap_or(DEFAULT_MAX_CPUS);
    usize::min(logical_cores, cores)
}

/// return the number of threads we should be using. The [ideal_threads] is that we can ideally
/// use but the [num_threads] is the value to use.
pub fn get_num_threads_to_use(num_cpus: usize) -> usize {
    // we always keep one thread free and some room for the management threads that monitor
    // the rule execution.
    let ideal_threads = ((num_cpus as f32 - 1.0) * 0.90) as usize;
    if ideal_threads == 0 {
        1
    } else {
        ideal_threads
    }
}

/// Prints the settings shared across products (SAST, secrets), regardless of which are enabled.
pub fn print_run_configuration(run_config: &RunConfiguration) {
    let configuration_method = match run_config.configuration_method {
        None => "none (no local file and no remote configuration)",
        Some(ConfigMethod::RemoteConfiguration) => "remote configuration",
        Some(ConfigMethod::RemoteConfigurationWithFile) => "remote configuration + local file",
        Some(ConfigMethod::File) => "local configuration file (yaml)",
    };

    let output_format_str = match run_config.output_format {
        OutputFormat::Csv => "csv",
        OutputFormat::Sarif => "sarif",
        OutputFormat::Json => "json",
    };

    println!("Configuration");
    println!("=============");
    println!("version                   : {}", CARGO_VERSION);
    println!("revision                  : {}", VERSION);
    println!("config method             : {}", configuration_method);
    println!("cores available           : {}", num_cpus::get());
    println!("cores used                : {}", run_config.num_cpus);
    println!(
        "source directory          : {}",
        run_config.source_directory
    );
    println!(
        "subdirectories            : {}",
        run_config.source_subdirectories.clone().join(",")
    );
    println!("output file               : {}", run_config.output_file);
    println!(
        "static analysis enabled   :  {}",
        run_config.static_analysis_enabled
    );
    println!("secrets enabled           : {}", run_config.secrets_enabled);
    println!("output format             : {}", output_format_str);
    println!("use debug                 : {}", run_config.use_debug);
    println!("use staging               : {}", run_config.use_staging);
}

/// Prints SAST's own settings. Only meaningful (and only called) when SAST is enabled.
pub fn print_sast_configuration(sast_config: &SastConfiguration) {
    let languages = get_languages_for_rules(&sast_config.rules);
    let languages_string: Vec<String> = languages.iter().map(|l| l.to_string()).collect();
    let ignore_paths_str = if sast_config.path_config.ignore.is_empty() {
        "no ignore path".to_string()
    } else {
        sast_config.path_config.ignore.join(",")
    };
    let only_paths_str = match &sast_config.path_config.only {
        Some(x) => x.join(","),
        None => "all paths".to_string(),
    };

    println!();
    println!("Static analysis");
    println!("---------------");
    println!("#static analysis rules    : {}", sast_config.rules.len());
    println!("ignore paths              : {}", ignore_paths_str);
    println!("only paths                : {}", only_paths_str);
    println!(
        "ignore gitignore          : {}",
        sast_config.ignore_gitignore
    );
    println!(
        "ignore gen files          : {}",
        sast_config.ignore_generated_files
    );
    println!("rules languages           : {}", languages_string.join(","));
    println!(
        "max file size             : {} kb",
        sast_config.max_file_size_kb
    );
}

/// Prints secrets' own settings. Only meaningful (and only called) when secrets is enabled.
pub fn print_secrets_configuration(secrets_config: &SecretsConfiguration) {
    let ignore_paths_str = if secrets_config.path_config.ignore.is_empty() {
        "no ignore path".to_string()
    } else {
        secrets_config.path_config.ignore.join(",")
    };
    let only_paths_str = match &secrets_config.path_config.only {
        Some(x) => x.join(","),
        None => "all paths".to_string(),
    };

    println!();
    println!("Secrets");
    println!("-------");
    println!("#secrets rules loaded     : {}", secrets_config.rules.len());
    println!("ignore paths              : {}", ignore_paths_str);
    println!("only paths                : {}", only_paths_str);
    println!(
        "ignore gitignore          : {}",
        secrets_config.ignore_gitignore
    );
    println!(
        "ignore gen files          : {}",
        secrets_config.ignore_generated_files
    );
    println!(
        "max file size             : {} kb",
        secrets_config.max_file_size_kb
    );
    println!("[experimental] ast filter : {}", secrets_config.ast_filter);
}
