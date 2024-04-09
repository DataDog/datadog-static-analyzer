use cli::config_file::read_config_file;
use cli::datadog_utils::{
    get_all_default_rulesets, get_diff_aware_information, get_rules_from_rulesets,
};
use cli::file_utils::{
    are_subdirectories_safe, filter_files_by_diff_aware_info, filter_files_by_size,
    filter_files_for_language, get_files, read_files_from_gitignore,
};
use cli::rule_utils::{
    count_violations_by_severities, get_languages_for_rules, get_rulesets_from_file,
};
use itertools::Itertools;
use kernel::analysis::analyze::analyze;
use kernel::constants::{CARGO_VERSION, VERSION};
use kernel::model::analysis::{AnalysisOptions, ERROR_RULE_TIMEOUT};
use kernel::model::common::{Language, OutputFormat};
use kernel::model::rule::{Rule, RuleInternal, RuleResult, RuleSeverity};

use anyhow::{Context, Result};
use cli::constants::DEFAULT_MAX_FILE_SIZE_KB;
use cli::csv;
use cli::model::cli_configuration::CliConfiguration;
use cli::model::datadog_api::DiffAwareData;
use cli::sarif::sarif_utils::{
    generate_sarif_report, SarifReportMetadata, SarifRule, SarifRuleResult,
};
use cli::secrets::{DetectedSecret, SecretRule};
use cli::violations_table;
use getopts::Options;
use indicatif::ProgressBar;
use kernel::config_file::ArgumentProvider;
use kernel::model::config_file::{ConfigFile, PathConfig};
use kernel::path_restrictions::PathRestrictions;
use kernel::rule_overrides::RuleOverrides;
use rayon::prelude::*;
use std::collections::HashMap;
use std::io::prelude::*;
use std::process::exit;
use std::time::{Instant, SystemTime};
use std::{env, fs};

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    print!("{}", opts.usage(&brief));
}

fn print_configuration(configuration: &CliConfiguration) {
    let configuration_method = if configuration.use_configuration_file {
        "config file (static-analysis.datadog.[yml|yaml])"
    } else {
        "rule file"
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
    println!("version             : {}", CARGO_VERSION);
    println!("revision            : {}", VERSION);
    println!("config method       : {}", configuration_method);
    println!("cores available     : {}", num_cpus::get());
    println!("cores used          : {}", configuration.num_cpus);
    println!("#rules loaded       : {}", configuration.rules.len());
    println!("source directory    : {}", configuration.source_directory);
    println!(
        "subdirectories      : {}",
        configuration.source_subdirectories.clone().join(",")
    );
    println!("output file         : {}", configuration.output_file);
    println!("output format       : {}", output_format_str);
    println!("ignore paths        : {}", ignore_paths_str);
    println!("only paths          : {}", only_paths_str);
    println!("ignore gitignore    : {}", configuration.ignore_gitignore);
    println!(
        "use config file     : {}",
        configuration.use_configuration_file
    );
    println!("use debug           : {}", configuration.use_debug);
    println!("use staging         : {}", configuration.use_staging);
    println!("rules languages     : {}", languages_string.join(","));
    println!(
        "max file size       : {} kb",
        configuration.max_file_size_kb
    );
}

/// Utility function to convert rules to rules internal.
/// Print the time to convert if the performance statistics switch is enabled.
fn convert_rules_to_rules_internal(
    configuration: &CliConfiguration,
    language: &Language,
) -> Result<Vec<RuleInternal>> {
    let rules_conversion_time = Instant::now();

    let rules = configuration
        .rules
        .iter()
        .filter(|r| r.language == *language)
        .map(|r| {
            let rule_conversion_time = Instant::now();

            let res = r
                .to_rule_internal()
                .context("cannot convert to rule internal");

            if configuration.show_performance_statistics {
                println!(
                    "Rule {} conversion to rule internal: {} ms",
                    r.name,
                    rule_conversion_time.elapsed().as_millis()
                );
            }

            res
        })
        .collect::<Result<Vec<_>>>();

    if configuration.show_performance_statistics {
        println!(
            "Total time to convert rules to rules internal for language {}: {} ms",
            language,
            rules_conversion_time.elapsed().as_millis()
        );
    }

    rules
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    #[allow(unused_assignments)]
    let mut use_configuration_file = false;
    let mut ignore_gitignore = false;
    let mut max_file_size_kb = DEFAULT_MAX_FILE_SIZE_KB;

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
    opts.optopt("f", "format", "format of the output file", "json/sarif/csv");
    opts.optopt("o", "output", "output file name", "output.json");
    opts.optflag(
        "",
        "print-violations",
        "print a list with all the violations that were found",
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
    opts.optflag(
        "g",
        "add-git-info",
        "add Git information to the SARIF report",
    );
    #[cfg(feature = "secrets")]
    {
        opts.optflag("", "test-secrets", "run the secret scanner in test mode");
        opts.optflag("", "validate-secrets", "attempt to validate secrets");
    }

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
        exit(1);
    }

    let should_verify_checksum = !matches.opt_present("b");
    let use_staging = matches.opt_present("s");
    let add_git_info = matches.opt_present("g");
    let enable_performance_statistics = matches.opt_present("x");
    let print_violations = matches.opt_present("print-violations");
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
        exit(1)
    }

    let directory_to_analyze = directory_to_analyze_option.unwrap();
    let directory_path = std::path::Path::new(&directory_to_analyze);

    if !directory_path.is_dir() {
        eprintln!("directory to analyze is not correct");
        exit(1)
    }

    if !are_subdirectories_safe(directory_path, &subdirectories_to_analyze) {
        eprintln!("sub-directories are not safe and point outside of the repository");
        exit(1)
    }

    let configuration_file: Option<ConfigFile> =
        match read_config_file(directory_to_analyze.as_str()) {
            Ok(cfg) => cfg,
            Err(err) => {
                eprintln!(
                    "Error reading configuration file from {}:\n  {}",
                    directory_to_analyze, err
                );
                exit(1)
            }
        };
    let mut rules: Vec<Rule> = Vec::new();
    let mut path_restrictions = PathRestrictions::default();
    let mut argument_provider = ArgumentProvider::new();

    // if there is a configuration file, we load the rules from it. But it means
    // we cannot have the rule parameter given.
    if let Some(conf) = configuration_file {
        use_configuration_file = true;
        ignore_gitignore = conf.ignore_gitignore.unwrap_or(false);
        if rules_file.is_some() {
            eprintln!("a rule file cannot be specified when a configuration file is present.");
            exit(1);
        }

        let overrides = RuleOverrides::from_config_file(&conf);

        let rulesets = conf.rulesets.keys().cloned().collect_vec();
        let rules_from_api = get_rules_from_rulesets(&rulesets, use_staging)
            .context("error when reading rules from API")?;
        rules.extend(rules_from_api.into_iter().map(|rule| Rule {
            severity: overrides.severity(&rule.name, rule.severity),
            category: overrides.category(&rule.name, rule.category),
            ..rule
        }));
        path_restrictions = PathRestrictions::from_ruleset_configs(&conf.rulesets);
        argument_provider = ArgumentProvider::from(&conf);

        // copy the only and ignore paths from the configuration file
        path_config.ignore.extend(conf.paths.ignore);
        path_config.only = conf.paths.only;

        // Get the max file size from the configuration or default to the default constant.
        max_file_size_kb = conf.max_file_size_kb.unwrap_or(DEFAULT_MAX_FILE_SIZE_KB)
    } else {
        use_configuration_file = false;
        // if there is no config file, we take the default rules from our APIs.
        if rules_file.is_none() {
            println!("WARNING: no configuration file detected, getting the default rules from the Datadog API");
            println!("Check the following resources to configure your rules:");
            println!(
                " - Datadog documentation: https://docs.datadoghq.com/code_analysis/static_analysis"
            );
            println!(" - Static analyzer repository on GitHub: https://github.com/DataDog/datadog-static-analyzer");
            let rulesets_from_api =
                get_all_default_rulesets(use_staging).expect("cannot get default rules");

            rules.extend(rulesets_from_api.into_iter().flat_map(|v| v.rules.clone()));
        } else {
            let rulesets_from_file = get_rulesets_from_file(rules_file.clone().unwrap().as_str());
            rules.extend(
                rulesets_from_file
                    .context("cannot read ruleset from file")?
                    .into_iter()
                    .flat_map(|v| v.rules),
            );
        }
    }

    // add ignore path from the options
    path_config
        .ignore
        .extend(ignore_paths_from_options.iter().map(|p| p.clone().into()));

    // ignore all directories that are in gitignore
    if !ignore_gitignore {
        let paths_from_gitignore = read_files_from_gitignore(directory_to_analyze.as_str())
            .expect("error when reading gitignore file");
        path_config
            .ignore
            .extend(paths_from_gitignore.iter().map(|p| p.clone().into()));
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
        use_configuration_file,
        ignore_gitignore,
        source_directory: directory_to_analyze.clone(),
        source_subdirectories: subdirectories_to_analyze.clone(),
        path_config,
        rules_file,
        output_format,
        num_cpus,
        rules,
        path_restrictions,
        argument_provider,
        output_file,
        max_file_size_kb,
        use_staging,
        show_performance_statistics: enable_performance_statistics,
    };

    print_configuration(&configuration);

    let mut all_rule_results = vec![];

    let analysis_options = AnalysisOptions {
        log_output: true,
        use_debug,
    };

    // verify rule checksum
    if should_verify_checksum {
        if configuration.use_debug {
            print!("Checking rule checksum ... ");
        }
        for r in &configuration.rules {
            if !r.verify_checksum() {
                panic!("Checksum invalid for rule {}", r.name);
            }
        }
        if configuration.use_debug {
            println!("done!");
        }
    } else {
        println!("Skipping checksum verification");
    }

    // check if we do a diff-aware scan
    let diff_aware_parameters: Option<DiffAwareData> = if diff_aware_requested {
        match configuration.generate_diff_aware_request_data() {
            Ok(params) => match get_diff_aware_information(&params) {
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
            },
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

    // we always keep one thread free and some room for the management threads that monitor
    // the rule execution.
    let ideal_threads = ((configuration.num_cpus as f32 - 1.0) * 0.90) as usize;
    let num_threads = if ideal_threads == 0 { 1 } else { ideal_threads };

    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()?;

    let mut total_files_analyzed: usize = 0;
    let start_timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

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

    ////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////
    // Secrets Test
    #[allow(unused_mut)]
    let mut detected_secrets = Vec::<DetectedSecret>::new();
    #[allow(unused_mut)]
    let mut secrets_rules = Vec::<SecretRule>::new();
    #[cfg(feature = "secrets")]
    if matches.opt_present("test-secrets") {
        use cli::secrets::ValidationStatus;
        use secrets::temp_integration_test::{build_secrets_engine, shannon_entropy};
        use std::sync::mpsc;
        use std::sync::mpsc::RecvTimeoutError;
        use std::sync::Arc;
        use std::time::Duration;

        secrets_rules.push(SecretRule::new(
            "datadog-api-key",
            "An API key unique to a Datadog organization that is required to submit metrics and events",
            "A Datadog API key",
        ));
        let should_validate = matches.opt_present("validate-secrets");

        println!("scanning {} files for secrets", files_to_analyze.len());
        let progress_bar =
            (!configuration.use_debug).then(|| ProgressBar::new(files_to_analyze.len() as u64));

        let start_timestamp = Instant::now();
        let engine = Arc::new(build_secrets_engine());
        let candidates = files_to_analyze
            .par_iter()
            .filter_map(|path| {
                let file_contents = fs::read(path).ok()?;
                let scan_result = engine.scan(path, &file_contents);
                if let Some(pb) = &progress_bar {
                    pb.inc(1);
                }
                // Temporary: swallow errors
                scan_result.map_err(drop).ok()
            })
            .filter(|candidates| !candidates.is_empty())
            // Temporary: implement this here, but conceptually this is a Matcher
            .flatten()
            .filter(|cand| {
                // For this test, we know all regexes have a capture named "candidate".
                let captured = cand.rule_match.captures.get("candidate").unwrap().as_str();
                // Included for this test, even though entropy will eventually be implemented as a Matcher.
                shannon_entropy(captured.chars().map(|ch| ch.to_ascii_lowercase()), 16) > 0.5
            })
            .collect::<Vec<_>>();

        let elapsed = start_timestamp.elapsed();
        println!(
            "secrets scan found {} candidates in {:.1}s",
            candidates.len(),
            elapsed.as_secs_f32()
        );
        let start_timestamp = Instant::now();

        // Temporary limit validation count to 100 to sidestep not having a threadpool to limit thread spawning
        let empty = vec![];
        let (with_validation, sans_validation) = match (candidates.len(), should_validate) {
            (_, false) => (empty.as_slice(), candidates.as_slice()),
            (0..=100, true) => (candidates.as_slice(), empty.as_slice()),
            (_, true) => candidates.split_at(100),
        };

        let (tx, rx) = mpsc::channel();
        for candidate in with_validation {
            let clone_tx = tx.clone();
            let engine = Arc::clone(&engine);
            let candidate = candidate.clone();
            let _ = std::thread::spawn(move || {
                let res = engine.validate_candidate(candidate.clone());
                clone_tx.send(res).unwrap();
            });
        }

        for candidate in sans_validation {
            let relative_path = candidate
                .source
                .strip_prefix(directory_path)
                // Temporary: panic here until we can refactor how `main` propagates errors
                .expect("path should under `directory_path`");
            // Access the hardcoded capture name "candidate"
            let captured = candidate.rule_match.captures.get("candidate").unwrap();
            let (start, end) = into_positions(captured.point_span);
            detected_secrets.push(DetectedSecret::new(
                candidate.rule_match.rule_id.to_string(),
                relative_path.to_string_lossy().to_string(),
                ValidationStatus::Unvalidated,
                start,
                end,
            ));
        }

        if !with_validation.is_empty() {
            let mut attempts = Vec::with_capacity(with_validation.len());
            loop {
                match rx.recv_timeout(Duration::from_secs(30)) {
                    Ok(val_attempt) => {
                        attempts.push(val_attempt);
                        if attempts.len() == with_validation.len() {
                            break;
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => break,
                    Err(RecvTimeoutError::Disconnected) => panic!("channel should not disconnect"),
                }
            }
            let mut completed = 0;
            for attempt in &attempts {
                // Temporary: swallow errors
                let Ok(result) = attempt else {
                    continue;
                };
                completed += 1;
                let (start, end) = into_positions(result.point_span());
                let relative_path = result
                    .source()
                    .strip_prefix(directory_path)
                    // Temporary: panic here until we can refactor how `main` propagates errors
                    .expect("path should under `directory_path`");
                detected_secrets.push(DetectedSecret::new(
                    result.rule_id().to_string(),
                    relative_path.to_string_lossy().to_string(),
                    into_val_status(result.category()),
                    start,
                    end,
                ));
            }

            let elapsed = start_timestamp.elapsed();
            let timed_out = with_validation.len() - completed;
            println!(
                "secrets validation performed in {:.1}s ({} completed, {} timed out)",
                elapsed.as_secs_f32(),
                completed,
                timed_out,
            );
        }

        if let Some(pb) = &progress_bar {
            pb.finish();
        }
    }
    ////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////

    let mut number_of_rules_used = 0;
    // Finally run the analysis
    for language in &languages {
        let files_for_language = filter_files_for_language(&files_to_analyze, language);

        if files_for_language.is_empty() {
            continue;
        }

        // we only use the progress bar when the debug mode is not active, otherwise, it puts
        // too much information on the screen.
        let progress_bar = if !configuration.use_debug {
            Some(ProgressBar::new(files_for_language.len() as u64))
        } else {
            None
        };
        total_files_analyzed += files_for_language.len();

        let rules_for_language: Vec<RuleInternal> =
            convert_rules_to_rules_internal(&configuration, language)?;

        number_of_rules_used += rules_for_language.len();

        println!(
            "Analyzing {} {:?} files using {} rules",
            files_for_language.len(),
            language,
            rules_for_language.len()
        );

        if use_debug {
            println!(
                "Analyzing {}, {} files detected",
                language,
                files_for_language.len()
            )
        }

        // take the relative path for the analysis
        let rule_results: Vec<RuleResult> = files_for_language
            .into_par_iter()
            .flat_map(|path| {
                let relative_path = path
                    .strip_prefix(directory_path)
                    .unwrap()
                    .to_str()
                    .expect("path contains non-Unicode characters");
                let mut selected_rules = rules_for_language
                    .iter()
                    .filter(|r| {
                        configuration
                            .path_restrictions
                            .rule_applies(&r.name, relative_path)
                    })
                    .peekable();
                let res = if selected_rules.peek().is_none() {
                    vec![]
                } else if let Ok(file_content) = fs::read_to_string(&path) {
                    analyze(
                        language,
                        selected_rules,
                        relative_path,
                        &file_content,
                        &configuration.argument_provider,
                        &analysis_options,
                    )
                } else {
                    eprintln!("error when getting content of path {}", &path.display());
                    vec![]
                };
                if let Some(pb) = &progress_bar {
                    pb.inc(1);
                }
                res
            })
            .collect();
        all_rule_results.append(rule_results.clone().as_mut());

        if let Some(pb) = &progress_bar {
            pb.finish();
        }
    }

    let end_timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let nb_violations: u32 = all_rule_results
        .iter()
        .map(|x| x.violations.len() as u32)
        .sum();

    let execution_time_secs = end_timestamp - start_timestamp;

    println!(
        "Found {} violation(s) in {} file(s) using {} rule(s) within {} sec(s)",
        nb_violations, total_files_analyzed, number_of_rules_used, execution_time_secs
    );

    // If the performance statistics are enabled, we show the total execution time per rule
    // and the rule that timed-out.
    if enable_performance_statistics {
        let mut rules_execution_time_ms: HashMap<String, u128> = HashMap::new();

        // first, get the rule execution time
        for rule_result in &all_rule_results {
            let current_value = rules_execution_time_ms
                .get(&rule_result.rule_name)
                .unwrap_or(&0u128);
            let new_value =
                current_value + rule_result.execution_time_ms + rule_result.query_node_time_ms;
            rules_execution_time_ms.insert(rule_result.rule_name.clone(), new_value);
        }

        println!("All rules execution time");
        println!("------------------------");
        // Show execution time, in sorted order
        for v in rules_execution_time_ms
            .iter()
            .sorted_by(|a, b| Ord::cmp(b.1, a.1))
            .as_slice()
        {
            println!("rule {:?} total analysis time {:?} ms", v.0, v.1);
        }

        println!("Top 100 slowest rules breakdown");
        println!("-------------------------------");
        // Show execution time, in sorted order
        for v in rules_execution_time_ms
            .iter()
            .sorted_by(|a, b| Ord::cmp(b.1, a.1))
            .take(100)
        {
            let rule_name = v.0;
            let mut query_node_time_ms: u128 = 0;
            let mut execution_time_ms: u128 = 0;
            let mut total_time_ms: u128 = 0;

            for rule_result in &all_rule_results {
                if rule_result.rule_name.eq(rule_name) {
                    query_node_time_ms += rule_result.query_node_time_ms;
                    execution_time_ms += rule_result.execution_time_ms;
                    total_time_ms = total_time_ms
                        + rule_result.query_node_time_ms
                        + rule_result.execution_time_ms;
                }
            }
            println!(
                "rule {:?}, total time {:?} ms, query node time {:?} ms, execution time {:?} ms",
                rule_name, total_time_ms, query_node_time_ms, execution_time_ms
            );
        }

        println!("Top 100 slowest files to parse");
        println!("------------------------------");
        let mut parsing_time_ms: HashMap<String, u128> = HashMap::new();

        // organize the map to have the parsing time by file
        for rule_result in &all_rule_results {
            if !parsing_time_ms.contains_key(&rule_result.filename) {
                parsing_time_ms.insert(rule_result.filename.clone(), rule_result.parsing_time_ms);
            }
        }

        for v in parsing_time_ms
            .iter()
            .sorted_by(|a, b| Ord::cmp(b.1, a.1))
            .take(100)
        {
            println!("file {:?}, parsing time {:?} ms", v.0, v.1);
        }

        // show the rules that timed out
        println!("Rule timed out");
        println!("--------------");
        let rules_timed_out: Vec<RuleResult> = all_rule_results
            .clone()
            .into_iter()
            .filter(|r| r.errors.contains(&ERROR_RULE_TIMEOUT.to_string()))
            .collect();
        if rules_timed_out.is_empty() {
            println!("No rule timed out");
        }
        for v in rules_timed_out {
            println!("Rule {} timed out on file {}", v.rule_name, v.filename);
        }
    }

    if print_violations && nb_violations > 0 {
        violations_table::print_violations_table(&all_rule_results);
    }

    let value = match configuration.output_format {
        OutputFormat::Csv => csv::generate_csv_results(&all_rule_results),
        OutputFormat::Json => {
            serde_json::to_string(&all_rule_results).expect("error when getting the JSON report")
        }
        OutputFormat::Sarif => {
            let mut rules: Vec<SarifRule> = configuration
                .rules
                .iter()
                .cloned()
                .map(|r| r.into())
                .collect();
            let mut results = all_rule_results
                .iter()
                .cloned()
                .map(SarifRuleResult::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(anyhow::Error::msg)?;

            rules.extend(secrets_rules.into_iter().map(SarifRule::from));
            let detected_secrets = detected_secrets
                .into_iter()
                .map(SarifRuleResult::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(anyhow::Error::msg)?;
            results.extend(detected_secrets);

            match generate_sarif_report(
                &rules,
                &results,
                &directory_to_analyze,
                SarifReportMetadata {
                    add_git_info,
                    debug: configuration.use_debug,
                    config_digest: configuration.generate_diff_aware_digest(),
                    diff_aware_parameters,
                    execution_time_secs,
                },
            ) {
                Ok(report) => {
                    serde_json::to_string(&report).expect("error when getting the SARIF report")
                }
                Err(_) => {
                    panic!("Error when generating the sarif report");
                }
            }
        }
    };

    // write the reports
    let mut file = fs::File::create(configuration.output_file).context("cannot create file")?;
    file.write_all(value.as_bytes())
        .context("error when writing results")?;

    // if there is any violation at all and --fail-on-any-violation is passed, we exit 1
    if !fail_any_violation_severities.is_empty()
        && count_violations_by_severities(&all_rule_results, &fail_any_violation_severities) > 0
    {
        exit(1);
    }

    Ok(())
}

const DEFAULT_MAX_CPUS: usize = 8;

/// Returns the user's requested core count, clamped to the number of logical cores on the system.
/// If unspecified, up to [DEFAULT_MAX_CPUS] CPUs will be used.
fn choose_cpu_count(user_input: Option<usize>) -> usize {
    let logical_cores = num_cpus::get();
    let cores = user_input.unwrap_or(DEFAULT_MAX_CPUS);
    usize::min(logical_cores, cores)
}

// Temporary to sidestep that we can't impl these across crates.
// When fully-integrated, these will be standard From impls
#[cfg(feature = "secrets")]
fn into_rule_severity(sev: secrets::temp_integration_test::Severity) -> RuleSeverity {
    use secrets::temp_integration_test::Severity;
    match sev {
        Severity::Error => RuleSeverity::Error,
        Severity::Warning => RuleSeverity::Warning,
        Severity::Notice => RuleSeverity::Notice,
        Severity::Info => RuleSeverity::None,
    }
}
#[cfg(feature = "secrets")]
fn into_positions(
    span: secrets::temp_integration_test::PointSpan,
) -> (
    kernel::model::common::Position,
    kernel::model::common::Position,
) {
    use kernel::model::common::Position;
    let start = Position {
        line: span.start().line.get(),
        col: span.start().col.get(),
    };
    let end = Position {
        line: span.end().line.get(),
        col: span.end().col.get(),
    };
    (start, end)
}

#[cfg(feature = "secrets")]
fn into_val_status(
    category: secrets::temp_integration_test::SecretCategory,
) -> cli::secrets::ValidationStatus {
    use cli::secrets::ValidationStatus;
    use secrets::temp_integration_test::SecretCategory;
    match category {
        SecretCategory::Valid(sev) => {
            let severity = into_rule_severity(sev);
            ValidationStatus::Valid(severity)
        }
        SecretCategory::Invalid(_) => ValidationStatus::Invalid,
        SecretCategory::Inconclusive(_) => ValidationStatus::Inconclusive,
    }
}
