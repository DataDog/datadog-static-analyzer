use anyhow::{Context, Result};
use getopts::Options;
use itertools::Itertools;
use std::path::PathBuf;

use cli::config_file::get_config;
use cli::constants::{
    DEFAULT_MAX_CPUS, DEFAULT_MAX_FILE_SIZE_KB, EXIT_CODE_FAIL_ON_VIOLATION,
    EXIT_CODE_INVALID_CONFIGURATION, EXIT_CODE_INVALID_DIRECTORY, EXIT_CODE_NO_DIRECTORY,
    EXIT_CODE_NO_OUTPUT, EXIT_CODE_RULESET_NOT_FOUND, EXIT_CODE_RULE_FILE_WITH_CONFIGURATION,
    EXIT_CODE_UNSAFE_SUBDIRECTORIES,
};
use cli::csv;
use cli::datadog_utils::{
    get_all_default_rulesets, get_diff_aware_information, get_rules_from_rulesets,
    get_secrets_rules, DatadogApiError,
};
use cli::file_utils::{
    are_subdirectories_safe, filter_files_by_diff_aware_info, filter_files_by_size, get_files,
    read_files_from_gitignore,
};
use cli::model::cli_configuration::CliConfiguration;
use cli::model::datadog_api::DiffAwareData;
use cli::rule_utils::{
    convert_secret_result_to_rule_result, count_violations_by_severities, get_languages_for_rules,
    get_rulesets_from_file,
};
use cli::sarif::sarif_utils::{generate_sarif_file, SarifReportMetadata};
use cli::utils::{choose_cpu_count, print_configuration};
use cli::violations_table;
use common::analysis_options::AnalysisOptions;
use common::model::diff_aware::DiffAware;
use datadog_static_analyzer::{secret_analysis, static_analysis, CliResults};
use kernel::analysis::ddsa_lib::v8_platform::{initialize_v8, Initialized, V8Platform};
use kernel::analysis::generated_content::DEFAULT_IGNORED_GLOBS;
use kernel::classifiers::ArtifactClassification;
use kernel::config::common::{ConfigFile, ConfigMethod, PathConfig};
use kernel::constants::{CARGO_VERSION, VERSION};
use kernel::model::common::OutputFormat;
use kernel::model::rule::{Rule, RuleSeverity};
use kernel::rule_config::RuleConfigProvider;
use secrets::model::secret_result::SecretValidationStatus;
use secrets::secret_files::should_ignore_file_for_secret;
use std::collections::HashMap;
use std::io::prelude::*;
use std::process::exit;
use std::time::{Duration, Instant};
use std::{env, fs};

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    #[allow(unused_assignments)]
    let mut ignore_gitignore = false;
    let mut max_file_size_kb = DEFAULT_MAX_FILE_SIZE_KB;
    let mut ignore_generated_files = true;

    opts.optopt(
        "i",
        "directory",
        "directory to scan (valid existing directory)",
        "/path/to/code/to/analyze",
    );
    opts.optmulti(
        "u",
        "subdirectory",
        "subdirectory to scan within the repository",
        "sub/directory",
    );
    opts.optopt(
        "r",
        "rules",
        "rules to use (json file)",
        "/path/to/rules.json",
    );
    opts.optopt("d", "debug", "use debug mode", "yes/no");
    opts.optflag("", "debug-export-java-dfa", "export Java flow graphs by writing a `{filename}.dot` file next to each Java file scanned; this dirties the working directory");
    opts.optopt("f", "format", "format of the output file", "json/sarif/csv");
    opts.optopt("o", "output", "output file name", "output.json");
    opts.optflag(
        "",
        "print-violations",
        "print a list with all the violations that were found",
    );
    opts.optopt(
        "",
        "enable-static-analysis",
        "enable/disable static analysis.",
        "yes,no,true,false (default 'true')",
    );
    opts.optopt(
        "",
        "enable-secrets",
        "enable/disable secrets scanning. Limited Availability feature. Requires using Datadog API keys.",
        "yes,no,true,false (default 'false')",
    );
    opts.optopt(
        "",
        "fail-on-any-violation",
        "exit a non-zero return code if there is one violation",
        "error,warning,notice,none",
    );
    opts.optopt(
        "c",
        "cpus",
        format!("allow N CPUs at once; if unspecified, defaults to the number of logical cores on the platform or {}, whichever is less", DEFAULT_MAX_CPUS).as_str(),
        "--cpus 5",
    );
    opts.optflag(
        "w",
        "diff-aware",
        "enable diff-aware scanning (only for Datadog users)",
    );
    opts.optflag(
        "",
        "secrets",
        "enable secrets detection (DEPRECATED, use enable-secrets)",
    );
    opts.optmulti(
        "p",
        "ignore-path",
        "path to ignore - the value is a glob",
        "**/test*.py (multiple values possible)",
    );
    opts.optflag("h", "help", "print this help");
    opts.optflag("v", "version", "shows the tool version");
    opts.optflag(
        "b",
        "bypass-checksum",
        "bypass checksum verification for the rules",
    );
    opts.optflag(
        "x",
        "performance-statistics",
        "enable performance statistics",
    );
    opts.optflag("s", "staging", "use staging");
    opts.optflag("t", "include-testing-rules", "include testing rules");
    opts.optflag(
        "g",
        "add-git-info",
        "add Git information to the SARIF report",
    );
    opts.optopt(
        "",
        "rule-timeout-ms",
        "how long a rule can run before being killed, in milliseconds",
        "1000",
    );

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            panic!("error when parsing arguments: {}", f)
        }
    };

    if matches.opt_present("v") {
        println!("Version: {}, revision: {}", CARGO_VERSION, VERSION);
        exit(0);
    }

    if matches.opt_present("h") {
        print_usage(&program, opts);
        exit(0);
    }

    let diff_aware_requested = matches.opt_present("w");

    if !matches.opt_present("o") {
        eprintln!("output file not specified");
        print_usage(&program, opts);
        exit(EXIT_CODE_NO_OUTPUT);
    }

    let should_verify_checksum = !matches.opt_present("b");
    let use_staging = matches.opt_present("s");
    let add_git_info = matches.opt_present("g");
    let enable_performance_statistics = matches.opt_present("x");
    let print_violations = matches.opt_present("print-violations");
    let secrets_enabled_old_option = matches.opt_present("secrets");

    // if --fail-on-any-violation is specified, get the list of severities to exit with a non-zero code
    let fail_any_violation_severities = match matches.opt_str("fail-on-any-violation") {
        Some(f) => f
            .split(',')
            .map(|s| RuleSeverity::try_from(s).expect("cannot map severity"))
            .collect(),
        None => {
            vec![]
        }
    };

    let output_format = match matches.opt_str("f") {
        Some(f) => match f.as_str() {
            "csv" => OutputFormat::Csv,
            "sarif" => OutputFormat::Sarif,
            _ => OutputFormat::Json,
        },
        None => OutputFormat::Json,
    };

    let use_debug = *matches
        .opt_str("d")
        .map(|value| value == "yes" || value == "true")
        .get_or_insert(env::var_os("DD_SA_DEBUG").is_some());

    // To remove once workload are migrated.
    if matches.opt_present("secrets") && use_debug {
        eprintln!("--secrets is deprecated, use --enabled-secrets true instead");
    }

    let debug_java_dfa = matches.opt_present("debug-export-java-dfa");
    let static_analysis_enabled = matches
        .opt_str("enable-static-analysis")
        .map(|value| value == "true" || value == "yes")
        .unwrap_or(true);
    let secrets_enabled_new_option = matches
        .opt_str("enable-secrets")
        .map(|value| value == "true" || value == "yes")
        .unwrap_or(false);
    let secrets_enabled = secrets_enabled_old_option || secrets_enabled_new_option;

    let output_file = matches
        .opt_str("o")
        .context("output file must be specified")?;

    let mut path_config = PathConfig {
        ignore: Vec::new(),
        only: None,
    };
    let ignore_paths_from_options = matches.opt_strs("p");
    let directory_to_analyze_option = matches.opt_str("i");
    let subdirectories_to_analyze = matches.opt_strs("u");

    let rules_file = matches.opt_str("r");

    if directory_to_analyze_option.is_none() {
        eprintln!("no directory passed, specify a directory with option -i");
        print_usage(&program, opts);
        exit(EXIT_CODE_NO_DIRECTORY)
    }

    let directory_to_analyze = directory_to_analyze_option.unwrap();
    let directory_path = std::path::Path::new(&directory_to_analyze);

    if !directory_path.is_dir() {
        eprintln!("directory to analyze is not correct");
        exit(EXIT_CODE_INVALID_DIRECTORY)
    }

    if !are_subdirectories_safe(directory_path, &subdirectories_to_analyze) {
        eprintln!("sub-directories are not safe and point outside of the repository");
        exit(EXIT_CODE_UNSAFE_SUBDIRECTORIES)
    }

    let configuration_file_and_method = get_config(directory_to_analyze.as_str(), use_debug);

    let (configuration_file, configuration_method): (Option<ConfigFile>, Option<ConfigMethod>) =
        match configuration_file_and_method {
            Ok(cfg) => match cfg {
                Some((config_file, config_method)) => (Some(config_file), Some(config_method)),
                _ => (None, None),
            },
            Err(err) => {
                eprintln!(
                    "Error reading configuration file from {}:\n  {}",
                    directory_to_analyze, err
                );
                exit(EXIT_CODE_INVALID_CONFIGURATION)
            }
        };

    if configuration_file.is_none() && use_debug {
        eprintln!("INFO: no configuration detected locally or remotely")
    }

    let rule_config_provider = configuration_file
        .as_ref()
        .map(RuleConfigProvider::from_config)
        .unwrap_or_default();
    let mut rules: Vec<Rule> = Vec::new();

    // if there is a configuration file, we load the rules from it. But it means
    // we cannot have the rule parameter given.
    if let Some(conf) = configuration_file {
        ignore_gitignore = conf.ignore_gitignore.unwrap_or(false);
        if rules_file.is_some() {
            eprintln!("a rule file cannot be specified when a configuration file is present.");
            exit(EXIT_CODE_RULE_FILE_WITH_CONFIGURATION);
        }

        if static_analysis_enabled {
            let rulesets = conf.rulesets.keys().cloned().collect_vec();
            let rules_from_api = get_rules_from_rulesets(&rulesets, use_staging, use_debug)
                .inspect_err(|e| {
                    if let DatadogApiError::RulesetNotFound(rs) = e {
                        eprintln!("Error: ruleset {rs} not found");
                        exit(EXIT_CODE_RULESET_NOT_FOUND);
                    }
                })
                .context("error when reading rules from API")?;
            rules.extend(rules_from_api);
        }
        // copy the only and ignore paths from the configuration file
        path_config.ignore.extend(conf.paths.ignore);
        path_config.only = conf.paths.only;

        // Get the max file size from the configuration or default to the default constant.
        max_file_size_kb = conf.max_file_size_kb.unwrap_or(DEFAULT_MAX_FILE_SIZE_KB);
        ignore_generated_files = conf.ignore_generated_files.unwrap_or(true);
    } else if static_analysis_enabled {
        // if there is no config file, we take the default rules from our APIs.
        if rules_file.is_none() {
            println!("WARNING: no configuration file detected, getting the default rules from the Datadog API");
            println!("Check the following resources to configure your rules:");
            println!(
                " - Datadog documentation: https://docs.datadoghq.com/code_analysis/static_analysis"
            );
            println!(" - Static analyzer repository on GitHub: https://github.com/DataDog/datadog-static-analyzer");
            let rulesets_from_api =
                get_all_default_rulesets(use_staging, use_debug).expect("cannot get default rules");

            rules.extend(rulesets_from_api.into_iter().flat_map(|rs| rs.into_rules()));
        } else {
            let rulesets_from_file = get_rulesets_from_file(rules_file.clone().unwrap().as_str());
            rules.extend(
                rulesets_from_file
                    .context("cannot read ruleset from file")?
                    .into_iter()
                    .flat_map(|rs| rs.into_rules()),
            );
        }
    }

    let secrets_rules = if secrets_enabled {
        get_secrets_rules(use_staging)?
    } else {
        vec![]
    };

    // add ignore path from the options
    path_config
        .ignore
        .extend(ignore_paths_from_options.iter().map(|p| p.clone().into()));

    // ignore all directories that are in gitignore
    if !ignore_gitignore {
        match read_files_from_gitignore(directory_to_analyze.as_str()) {
            Ok(paths_from_gitignore) => {
                path_config
                    .ignore
                    .extend(paths_from_gitignore.iter().map(|p| p.clone().into()));
            }
            Err(e) => {
                eprintln!("Warning: error when reading .gitignore file: {}", e);
                eprintln!("Continuing without .gitignore patterns");
            }
        }
    }
    if ignore_generated_files {
        path_config
            .ignore
            .extend(DEFAULT_IGNORED_GLOBS.iter().map(|&p| p.to_string().into()));
    }

    let languages = get_languages_for_rules(&rules);

    let files_in_repository = get_files(
        directory_to_analyze.as_str(),
        subdirectories_to_analyze.clone(),
        &path_config,
    )
    .expect("unable to get the list of files to analyze");

    let num_cores_requested = matches
        .opt_str("c")
        .map(|val| {
            val.parse::<usize>()
                .context("unable to parse `cpus` flag as integer")
        })
        .transpose()?;
    // Select the number of cores to use based on the user's CLI arg (or lack of one)
    let num_cpus = choose_cpu_count(num_cores_requested);

    // build the configuration object that contains how the CLI should behave.
    let configuration = CliConfiguration {
        use_debug,
        configuration_method,
        ignore_gitignore,
        source_directory: directory_to_analyze.clone(),
        source_subdirectories: subdirectories_to_analyze.clone(),
        path_config,
        rules_file,
        output_format,
        num_cpus,
        rules,
        rule_config_provider,
        output_file,
        max_file_size_kb,
        use_staging,
        show_performance_statistics: enable_performance_statistics,
        ignore_generated_files,
        static_analysis_enabled,
        secrets_enabled,
        secrets_rules: secrets_rules.clone(),
        should_verify_checksum,
        debug_java_dfa,
    };

    print_configuration(&configuration);

    let timeout = matches
        .opt_str("rule-timeout-ms")
        .map(|val| {
            val.parse::<u64>()
                .map(Duration::from_millis)
                .context("unable to parse `rule-timeout-ms` flag as integer")
        })
        .transpose()?;

    let analysis_options = AnalysisOptions {
        log_output: true,
        use_debug,
        ignore_generated_files,
        timeout,
    };

    // check if we do a diff-aware scan
    let diff_aware_parameters: Option<DiffAwareData> = if diff_aware_requested {
        match configuration.generate_diff_aware_request_data(configuration.use_debug) {
            Ok(params) => {
                if configuration.use_debug {
                    println!(
                        "Diff-aware request with sha {}, branch {}, config hash {}",
                        params.sha, params.branch, params.config_hash
                    );
                }

                match get_diff_aware_information(&params, configuration.use_debug) {
                    Ok(d) => {
                        if configuration.use_debug {
                            println!(
                                "diff aware enabled, base sha: {}, files to scan {}",
                                d.base_sha,
                                d.files.join(",")
                            );
                        } else {
                            println!(
                                "diff-aware enabled, based sha {}, scanning only {}/{} files",
                                d.base_sha,
                                d.files.len(),
                                files_in_repository.len()
                            )
                        }
                        Some(d)
                    }
                    Err(e) => {
                        eprintln!("diff aware not enabled (error when receiving diff-aware data from Datadog with config hash {}, sha {}), proceeding with full scan.", &params.config_hash, &params.sha);
                        if configuration.use_debug {
                            eprintln!("error when trying to enabled diff-aware scanning: {:?}", e);
                        }

                        None
                    }
                }
            }
            Err(e) => {
                eprintln!("diff aware not enabled (unable to generate diff-aware request data), proceeding with full scan.");
                eprintln!("Make sure the user running the scan owns the repository (use git config --global --add safe.directory <repo-path> if needed)");
                eprintln!("You can run the analyzer with --debug true to get more details about the error");
                eprintln!("Proceeding with full scan");

                if configuration.use_debug {
                    eprintln!("error when trying to enabled diff-aware scanning: {:?}", e);
                }

                None
            }
        }
    } else {
        None
    };

    if configuration.use_debug {
        println!("diff aware data: {:?}", diff_aware_parameters);
    }

    let mut v8: Option<V8Platform<Initialized>> = None;
    if static_analysis_enabled {
        let platform = initialize_v8(configuration.get_num_threads() as u32);
        _ = v8.insert(platform)
    }

    // This must be called _after_ `initialize_v8` (otherwise, PKU-related segfaults on Linux will occur).
    rayon::ThreadPoolBuilder::new()
        .num_threads(configuration.get_num_threads())
        .build_global()?;

    let files_filtered_by_size = filter_files_by_size(&files_in_repository, &configuration);

    // if diff-aware is enabled, we filter the files and keep only the files we want to analyze from diff-aware
    let files_to_analyze = if let Some(dap) = &diff_aware_parameters {
        filter_files_by_diff_aware_info(&files_filtered_by_size, directory_path, dap)
    } else {
        files_filtered_by_size
    };

    if configuration.use_debug && diff_aware_parameters.is_some() {
        println!(
            "{} files to scan with diff-aware: {}",
            files_to_analyze.len(),
            files_to_analyze
                .iter()
                .map(|x| x.as_os_str().to_str().unwrap().to_string())
                .join(",")
        );
    }

    let global_start_time = Instant::now();

    let mut all_path_metadata = HashMap::<String, ArtifactClassification>::new();
    let mut result: CliResults = CliResults {
        static_analysis: None,
        secrets: None,
    };
    if static_analysis_enabled {
        let static_analysis_start = Instant::now();

        let execution_result = static_analysis(
            v8.expect("v8 should have been initialized manually"),
            &configuration,
            &analysis_options,
            &files_to_analyze,
            &languages,
        )
        .context("static_analysis should have succeeded")?;

        let rules_results = &execution_result.rule_results;

        let nb_violations: u32 = rules_results
            .iter()
            .map(|x| x.violations.len() as u32)
            .sum();

        let static_analysis_metadata = &execution_result.metadata;

        let number_of_rules_used = rules_results
            .iter()
            .unique_by(|v| v.rule_name.as_str())
            .count();

        let total_files_analyzed = rules_results
            .iter()
            .unique_by(|v| v.filename.as_str())
            .count();

        all_path_metadata.extend(static_analysis_metadata.clone());

        println!(
            "Found {} violation(s) in {} file(s) using {} rule(s) within {} sec(s)",
            nb_violations,
            total_files_analyzed,
            number_of_rules_used,
            static_analysis_start.elapsed().as_secs()
        );

        result.static_analysis = Some(execution_result);
    }

    // Secrets detection

    if secrets_enabled {
        let secrets_start = Instant::now();

        let secrets_files: Vec<PathBuf> = files_in_repository
            .into_iter()
            .filter(|f| !should_ignore_file_for_secret(f))
            .collect();

        let execution_results = secret_analysis(&configuration, &analysis_options, &secrets_files)
            .context("secrets should execute with success")?;

        let secrets_rules_results = &execution_results.rule_results;

        let nb_secrets_found: u32 = secrets_rules_results
            .iter()
            .map(|x| x.matches.len() as u32)
            .sum();
        let nb_secrets_validated: u32 = secrets_rules_results
            .iter()
            .map(|x| {
                x.matches
                    .iter()
                    .filter(|m| m.validation_status == SecretValidationStatus::Valid)
                    .collect::<Vec<_>>()
                    .len() as u32
            })
            .sum();

        // adding metadata from secrets
        for (k, v) in &execution_results.metadata {
            if !all_path_metadata.contains_key(k) {
                all_path_metadata.insert(k.clone(), v.clone());
            }
        }

        let number_of_rules_used = secrets_rules_results
            .iter()
            .unique_by(|v| v.rule_name.as_str())
            .count();

        let total_files_analyzed = secrets_rules_results
            .iter()
            .unique_by(|v| v.filename.as_str())
            .count();

        println!(
            "Found {} secret(s) (including {} valid) in {} file(s) using {} rule(s) within {} sec(s)",
            nb_secrets_found,
            nb_secrets_validated,
            total_files_analyzed,
            number_of_rules_used,
            secrets_start.elapsed().as_secs()
        );

        result.secrets = Some(execution_results);
    }

    let global_execution_time_secs = global_start_time.elapsed().as_secs();

    // if we have more than one static analysis violation and printing is enabled, show all
    // violations

    let static_analysis_rule_results = result.static_analysis.take();
    let static_analysis_rule_results = static_analysis_rule_results
        .map(|r| r.rule_results)
        .unwrap_or_default();

    let secrets_violations = result.secrets.take();
    let secrets_violations = secrets_violations
        .map(|r| r.rule_results)
        .unwrap_or_default();

    let nb_total_static_analysis_violations: usize = static_analysis_rule_results
        .iter()
        .map(|x| x.violations.len())
        .sum();

    if print_violations && nb_total_static_analysis_violations > 0 {
        violations_table::print_violations_table(&static_analysis_rule_results);
    }

    // if there is any violation at all and --fail-on-any-violation is passed, we exit 1
    let fail_on_violations = !fail_any_violation_severities.is_empty()
        && count_violations_by_severities(
            &static_analysis_rule_results,
            &fail_any_violation_severities,
        ) > 0;

    let value = match configuration.output_format {
        OutputFormat::Csv => {
            csv::generate_csv_results(&static_analysis_rule_results, &secrets_violations)
        }
        OutputFormat::Json => {
            let combined_results = [
                secrets_violations
                    .iter()
                    .map(convert_secret_result_to_rule_result)
                    .collect(),
                static_analysis_rule_results,
            ]
            .concat();
            serde_json::to_string(&combined_results).expect("error when getting the JSON report")
        }
        OutputFormat::Sarif => generate_sarif_file(
            &configuration,
            static_analysis_rule_results,
            secrets_violations,
            SarifReportMetadata {
                add_git_info,
                debug: configuration.use_debug,
                config_digest: configuration.generate_diff_aware_digest(),
                diff_aware_parameters,
                execution_time_secs: global_execution_time_secs,
            },
            &all_path_metadata,
        )
        .expect("cannot generate SARIF results"),
    };

    // write the reports
    let mut file = fs::File::create(configuration.output_file).context("cannot create file")?;
    file.write_all(value.as_bytes())
        .context("error when writing results")?;

    // if there is any violation at all and --fail-on-any-violation is passed, we exit 1
    if fail_on_violations {
        exit(EXIT_CODE_FAIL_ON_VIOLATION);
    }

    Ok(())
}
