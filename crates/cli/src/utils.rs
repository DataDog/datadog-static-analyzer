use crate::constants::DEFAULT_MAX_CPUS;
use crate::model::cli_configuration::CliConfiguration;
use crate::rule_utils::get_languages_for_rules;
use kernel::constants::{CARGO_VERSION, VERSION};
use kernel::model::common::OutputFormat;
use kernel::model::config_file::ConfigMethod;

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

pub fn print_configuration(configuration: &CliConfiguration) {
    let configuration_method = match configuration.configuration_method {
        None => "none (no local file and no remote configuration)",
        Some(ConfigMethod::RemoteConfiguration) => "remote configuration",
        Some(ConfigMethod::RemoteConfigurationWithFile) => "remote configuration + local file",
        Some(ConfigMethod::File) => "local config file (static-analysis.datadog.[yml|yaml])",
    };

    let output_format_str = match configuration.output_format {
        OutputFormat::Csv => "csv",
        OutputFormat::Sarif => "sarif",
        OutputFormat::Json => "json",
    };

    let languages = get_languages_for_rules(&configuration.rules);
    let languages_string: Vec<String> = languages.iter().map(|l| l.to_string()).collect();
    let ignore_paths_str = if configuration.path_config.ignore.is_empty() {
        "no ignore path".to_string()
    } else {
        configuration.path_config.ignore.join(",")
    };
    let only_paths_str = match &configuration.path_config.only {
        Some(x) => x.join(","),
        None => "all paths".to_string(),
    };

    println!("Configuration");
    println!("=============");
    println!("version                 : {}", CARGO_VERSION);
    println!("revision                : {}", VERSION);
    println!("config method           : {}", configuration_method);
    println!("cores available         : {}", num_cpus::get());
    println!("cores used              : {}", configuration.num_cpus);
    println!("#static analysis rules  : {}", configuration.rules.len());

    if configuration.secrets_enabled {
        println!(
            "#secrets rules loaded   : {}",
            configuration.secrets_rules.len()
        );
    }

    println!(
        "source directory        : {}",
        configuration.source_directory
    );
    println!(
        "subdirectories          : {}",
        configuration.source_subdirectories.clone().join(",")
    );

    println!("output file             : {}", configuration.output_file);
    println!(
        "static analysis enabled:  {}",
        configuration.static_analysis_enabled
    );
    println!(
        "secrets enabled         : {}",
        configuration.secrets_enabled
    );
    println!("output format           : {}", output_format_str);
    println!("ignore paths            : {}", ignore_paths_str);
    println!("only paths              : {}", only_paths_str);
    println!(
        "ignore gitignore        : {}",
        configuration.ignore_gitignore
    );
    println!("use debug               : {}", configuration.use_debug);
    println!("use staging             : {}", configuration.use_staging);
    println!(
        "ignore gen files        : {}",
        configuration.ignore_generated_files
    );
    println!("rules languages         : {}", languages_string.join(","));
    println!(
        "max file size           : {} kb",
        configuration.max_file_size_kb
    );
}
