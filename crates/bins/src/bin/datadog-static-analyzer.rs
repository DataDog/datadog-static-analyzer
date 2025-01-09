use anyhow::{Context, Result};
use getopts::Options;
use indicatif::ProgressBar;
use itertools::Itertools;
use rayon::prelude::*;
use std::collections::HashMap;
use std::io::prelude::*;
use std::path::PathBuf;
use std::process::exit;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use std::{env, fs};

use cli::config_file::get_config;
use cli::constants::{
    DEFAULT_MAX_CPUS, DEFAULT_MAX_FILE_SIZE_KB, EXIT_CODE_FAIL_ON_VIOLATION,
    EXIT_CODE_INVALID_CONFIGURATION, EXIT_CODE_INVALID_DIRECTORY, EXIT_CODE_NO_DIRECTORY,
    EXIT_CODE_NO_OUTPUT, EXIT_CODE_RULESET_NOT_FOUND, EXIT_CODE_RULE_CHECKSUM_INVALID,
    EXIT_CODE_RULE_FILE_WITH_CONFIGURATION, EXIT_CODE_UNSAFE_SUBDIRECTORIES,
};
use cli::csv;
use cli::datadog_utils::{
    get_all_default_rulesets, get_diff_aware_information, get_rules_from_rulesets,
    get_secrets_rules, DatadogApiError,
};
use cli::file_utils::{
    are_subdirectories_safe, filter_files_by_diff_aware_info, filter_files_by_size,
    filter_files_for_language, get_files, read_files_from_gitignore,
};
use cli::model::cli_configuration::CliConfiguration;
use cli::model::datadog_api::DiffAwareData;
use cli::rule_utils::{
    check_rules_checksum, convert_rules_to_rules_internal, convert_secret_result_to_rule_result,
    count_violations_by_severities, get_languages_for_rules, get_rulesets_from_file,
};
use cli::sarif::sarif_utils::{generate_sarif_file, SarifReportMetadata};
use cli::utils::{choose_cpu_count, get_num_threads_to_use, print_configuration};
use cli::violations_table;
use common::analysis_options::AnalysisOptions;
use common::model::diff_aware::DiffAware;
use kernel::analysis::analyze::{analyze_with, generate_flow_graph_dot};
use kernel::analysis::ddsa_lib::v8_platform::initialize_v8;
use kernel::analysis::ddsa_lib::JsRuntime;
use kernel::analysis::generated_content::DEFAULT_IGNORED_GLOBS;
use kernel::classifiers::{is_test_file, ArtifactClassification};
use kernel::constants::{CARGO_VERSION, VERSION};
use kernel::model::analysis::ERROR_RULE_TIMEOUT;
use kernel::model::common::{Language, OutputFormat};
use kernel::model::config_file::{ConfigFile, ConfigMethod, PathConfig};
use kernel::model::rule::{Rule, RuleInternal, RuleResult, RuleSeverity};
use kernel::rule_config::RuleConfigProvider;
use secrets::model::secret_result::{SecretResult, SecretValidationStatus};
use secrets::scanner::{build_sds_scanner, find_secrets};
use secrets::secret_files::should_ignore_file_for_secret;
use std::cell::Cell;

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
    opts.optflag("", "secrets", "enable secrets detection (BETA)");
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
    let secrets_enabled = matches.opt_present("secrets");
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
    let debug_java_dfa = matches.opt_present("debug-export-java-dfa");

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

        // copy the only and ignore paths from the configuration file
        path_config.ignore.extend(conf.paths.ignore);
        path_config.only = conf.paths.only;

        // Get the max file size from the configuration or default to the default constant.
        max_file_size_kb = conf.max_file_size_kb.unwrap_or(DEFAULT_MAX_FILE_SIZE_KB);
        ignore_generated_files = conf.ignore_generated_files.unwrap_or(true);
    } else {
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
        let paths_from_gitignore = read_files_from_gitignore(directory_to_analyze.as_str())
            .expect("error when reading gitignore file");
        path_config
            .ignore
            .extend(paths_from_gitignore.iter().map(|p| p.clone().into()));
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
        secrets_enabled,
        secrets_rules: secrets_rules.clone(),
    };

    print_configuration(&configuration);

    let mut all_rule_results = Vec::<RuleResult>::new();
    let mut all_stats = AnalysisStatistics::new();
    // (Option<T> is used to prevent checking the same file path multiple times).
    let mut all_path_metadata = HashMap::<String, Option<ArtifactClassification>>::new();

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

    if should_verify_checksum {
        if let Err(e) = check_rules_checksum(configuration.rules.as_slice()) {
            eprintln!("error when checking rules checksum: {e}");
            exit(EXIT_CODE_RULE_CHECKSUM_INVALID)
        }
    }

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

    let num_threads = get_num_threads_to_use(&configuration);

    let v8 = initialize_v8(num_threads as u32);

    // This must be called _after_ `initialize_v8` (otherwise, PKU-related segfaults on Linux will occur).
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
            );
        }

        // take the relative path for the analysis
        let (stats, rule_results, path_metadata) = files_for_language
            .into_par_iter()
            .fold(
                || (AnalysisStatistics::new(), Vec::new(), HashMap::new()),
                |(mut stats, mut fold_results, mut path_metadata), path| {
                    thread_local! {
                        // (`Cell` is used to allow lazy instantiation of a thread local with zero runtime cost).
                        static JS_RUNTIME: Cell<Option<JsRuntime>> = const { Cell::new(None) };
                    }

                    let relative_path = path
                        .strip_prefix(directory_path)
                        .unwrap()
                        .to_str()
                        .expect("path contains non-Unicode characters");
                    let relative_path: Arc<str> = Arc::from(relative_path);
                    let rule_config = configuration
                        .rule_config_provider
                        .config_for_file(relative_path.as_ref());
                    let res = if let Ok(file_content) = fs::read_to_string(&path) {
                        let mut opt = JS_RUNTIME.replace(None);
                        let runtime_ref = opt.get_or_insert_with(|| {
                            v8.try_new_runtime().expect("ddsa init should succeed")
                        });

                        let file_content = Arc::from(file_content);
                        let mut results = analyze_with(
                            runtime_ref,
                            language,
                            &rules_for_language,
                            &relative_path,
                            &file_content,
                            &rule_config,
                            &analysis_options,
                        );
                        results.retain_mut(|r| {
                            // We'll drop all `RuleResult` that don't contain violations
                            let should_retain = !r.violations.is_empty();

                            // Register the timings:
                            // (The `RuleResult` vector for `errors` contains exactly 0 or 1 elements)
                            if let Some(err) = r.errors.first() {
                                if err == ERROR_RULE_TIMEOUT {
                                    stats.mark_timeout(&r.filename, &r.rule_name);
                                } else {
                                    stats.mark_error(&r.filename, &r.rule_name);
                                }
                            }
                            let exe_time = Duration::from_millis(r.execution_time_ms as u64);
                            stats.execution(&r.rule_name, exe_time);
                            let query_time = Duration::from_millis(r.query_node_time_ms as u64);
                            stats.query(&r.rule_name, query_time);
                            // For stats: re-use the RuleResult's allocation if it's going to be dropped anyway.
                            let filename = if should_retain {
                                r.filename.clone()
                            } else {
                                std::mem::take(&mut r.filename)
                            };
                            stats.parse(filename, Duration::from_millis(r.parsing_time_ms as u64));

                            should_retain
                        });

                        if debug_java_dfa && *language == Language::Java {
                            if let Some(graph) = generate_flow_graph_dot(
                                runtime_ref,
                                *language,
                                &relative_path,
                                &file_content,
                                &rule_config,
                                &analysis_options,
                            ) {
                                let dot_path = path.with_extension("dot");
                                let _ = fs::write(dot_path, graph);
                            }
                        }
                        JS_RUNTIME.replace(opt);

                        if !results.is_empty()
                            && !path_metadata.contains_key(relative_path.as_ref())
                        {
                            let cloned_path_str = relative_path.to_string();
                            let metadata = if is_test_file(
                                *language,
                                file_content.as_ref(),
                                std::path::Path::new(&cloned_path_str),
                                None,
                            ) {
                                Some(ArtifactClassification { is_test_file: true })
                            } else {
                                None
                            };
                            path_metadata.insert(cloned_path_str, metadata);
                        }

                        results
                    } else {
                        eprintln!("error when getting content of path {}", &path.display());
                        vec![]
                    };

                    if let Some(pb) = &progress_bar {
                        pb.inc(1);
                    }
                    fold_results.extend(res);

                    (stats, fold_results, path_metadata)
                },
            )
            .reduce(
                || (AnalysisStatistics::new(), Vec::new(), HashMap::new()),
                |mut base, other| {
                    let (other_stats, other_results, other_classifications) = other;
                    base.0 += other_stats;
                    base.1.extend(other_results);
                    for (k, v) in other_classifications {
                        let existing = base.2.insert(k, v);
                        // Due to the way the file paths are parallelized, even with rayon's work-stealing,
                        // there should never be a duplicate key (i.e., file path) between two rayon threads.
                        debug_assert!(existing.is_none());
                    }
                    base
                },
            );
        all_rule_results.extend(rule_results);
        all_stats += stats;
        for (k, v) in path_metadata {
            let existing = all_path_metadata.insert(k, v);
            // The `path_metadata` map will only contain file paths for a single `Language`.
            // Because a file only (currently) maps to a single `Language`, it's guaranteed that
            // the key will be unique.
            debug_assert!(existing.is_none());
        }

        if let Some(pb) = &progress_bar {
            pb.finish();
        }
    }
    let all_path_metadata = all_path_metadata
        .into_iter()
        .filter_map(|(k, v)| v.map(|classification| (k, classification)))
        .collect::<HashMap<_, _>>();

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

    // Secrets detection
    let mut secrets_results: Vec<SecretResult> = vec![];
    if secrets_enabled {
        let secrets_start = Instant::now();

        let secrets_files: Vec<PathBuf> = files_to_analyze
            .into_iter()
            .filter(|f| !should_ignore_file_for_secret(f))
            .collect();
        let progress_bar = if !configuration.use_debug {
            Some(ProgressBar::new(secrets_files.len() as u64))
        } else {
            None
        };

        let sds_scanner = build_sds_scanner(&secrets_rules, use_debug);

        let nb_secrets_rules: usize = secrets_rules.len();
        let nb_secrets_files = secrets_files.len();

        secrets_results = secrets_files
            .par_iter()
            .flat_map(|path| {
                let relative_path = path
                    .strip_prefix(directory_path)
                    .unwrap()
                    .to_str()
                    .expect("path contains non-Unicode characters");
                let res = if let Ok(file_content) = fs::read_to_string(path) {
                    let file_content = Arc::from(file_content);
                    find_secrets(
                        &sds_scanner,
                        &secrets_rules,
                        relative_path,
                        &file_content,
                        &analysis_options,
                    )
                } else {
                    // this is generally because the file is binary.
                    if use_debug {
                        eprintln!("error when getting content of path {}", &path.display());
                    }
                    vec![]
                };
                if let Some(pb) = &progress_bar {
                    pb.inc(1);
                }
                res
            })
            .collect();

        let nb_secrets_found: u32 = secrets_results.iter().map(|x| x.matches.len() as u32).sum();
        let nb_secrets_validated: u32 = secrets_results
            .iter()
            .map(|x| {
                x.matches
                    .iter()
                    .filter(|m| m.validation_status == SecretValidationStatus::Valid)
                    .collect::<Vec<_>>()
                    .len() as u32
            })
            .sum();

        if let Some(pb) = &progress_bar {
            pb.finish();
        }

        let secrets_execution_time_secs = secrets_start.elapsed().as_secs();

        println!(
            "Found {} secret(s) (including {} valid) in {} file(s) using {} rule(s) within {} sec(s)",
            nb_secrets_found,
            nb_secrets_validated,
            nb_secrets_files,
            nb_secrets_rules,
            secrets_execution_time_secs
        );
    }

    // If the performance statistics are enabled, we show the total execution time per rule
    // and the rule that timed-out.
    if enable_performance_statistics {
        // The time spent performing a tree-sitter query and running the JavaScript
        let mut analysis_times = Vec::<(&str, Duration, Duration, usize)>::with_capacity(
            all_stats.agg_execution_time.len(),
        );
        for (rule, execution) in &all_stats.agg_execution_time {
            let query = all_stats
                .agg_query_time
                .get(rule)
                .expect("query should exist if execution does");
            analysis_times.push((
                rule.as_str(),
                query.time,
                execution.time,
                execution.sample_count,
            ));
        }

        println!("All rules execution time");
        println!("------------------------");
        // Sort by total analysis time, descending
        analysis_times
            .sort_by_key(|&(_, query, execution, _)| std::cmp::Reverse(query + execution));

        for &(name, query, execution, count) in &analysis_times {
            let total_millis = (query + execution).as_millis();
            println!(
                "rule {:?} total analysis time {:?} ms in {:?} files",
                name, total_millis, count
            );
        }

        println!("Top 100 slowest rules breakdown");
        println!("-------------------------------");
        // Show execution time breakdown in descending order.
        for &(name, query, execution, _) in analysis_times.iter().take(100) {
            let total = (query + execution).as_millis();
            let query = query.as_millis();
            let execution = execution.as_millis();
            println!(
                "rule {:?}, total time {:?} ms, query node time {:?} ms, execution time {:?} ms",
                name, total, query, execution
            );
        }

        println!("Top {} slowest files to parse", STATS_MAX_PARSE_TIMES);
        println!("------------------------------");
        for (time, filename) in all_stats.file_parse_time.iter().rev() {
            let time = time.as_millis();
            println!("file {:?}, parsing time {:?} ms", filename, time);
        }

        // show the rules that timed out
        println!("Rule timed out");
        println!("--------------");
        if all_stats.execution_timeouts.is_empty() {
            println!("No rule timed out");
        }
        for (rule_name, files) in &all_stats.execution_timeouts {
            for filename in files {
                println!("Rule {} timed out on file {}", rule_name, filename);
            }
        }
    }

    if print_violations && nb_violations > 0 {
        violations_table::print_violations_table(&all_rule_results);
    }

    // if there is any violation at all and --fail-on-any-violation is passed, we exit 1
    let fail_on_violations = !fail_any_violation_severities.is_empty()
        && count_violations_by_severities(&all_rule_results, &fail_any_violation_severities) > 0;

    let value = match configuration.output_format {
        OutputFormat::Csv => csv::generate_csv_results(&all_rule_results, &secrets_results),
        OutputFormat::Json => {
            let combined_results = [
                secrets_results
                    .iter()
                    .map(convert_secret_result_to_rule_result)
                    .collect(),
                all_rule_results.clone(),
            ]
            .concat();
            serde_json::to_string(&combined_results).expect("error when getting the JSON report")
        }
        OutputFormat::Sarif => generate_sarif_file(
            &configuration,
            all_rule_results,
            secrets_results,
            SarifReportMetadata {
                add_git_info,
                debug: configuration.use_debug,
                config_digest: configuration.generate_diff_aware_digest(),
                diff_aware_parameters,
                execution_time_secs,
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

// The `AnalysisStatistics` struct is "tacked" onto this file here.
// We'll eventually refactor this to be implemented with tracing and the subscriber pattern.
// Thus, this should be seen as a temporary implementation.

type RuleName = String;
type FileName = String;

/// The maximum number of file parse times to store in an [`AnalysisStatistic`] `file_parse_time` heap.
const STATS_MAX_PARSE_TIMES: usize = 100;

/// A struct containing statistics about an analysis.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct AnalysisStatistics {
    /// The per-rule aggregate amount of time spent on a v8 execution.
    agg_execution_time: HashMap<RuleName, Aggregate>,
    /// The per-rule aggregate amount of time spent on performing tree-sitter queries.
    agg_query_time: HashMap<RuleName, Aggregate>,
    /// The per-rule list of filenames that timed out.
    execution_timeouts: HashMap<RuleName, Vec<FileName>>,
    /// The per-rule list of filenames that caused an execution error.
    execution_errors: HashMap<RuleName, Vec<FileName>>,
    /// A max heap of the per-file amount of time spent on tree-sitter tree parsing.
    file_parse_time: std::collections::BTreeSet<(Duration, FileName)>,
}

impl AnalysisStatistics {
    /// Creates a new, empty `AnalysisStatistics`.
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    /// Adds the execution time for the given `rule_name` to its aggregate.
    pub fn execution(&mut self, rule_name: &str, elapsed: Duration) {
        Self::increment_aggregate(rule_name, elapsed, &mut self.agg_execution_time);
    }

    /// Adds the tree-sitter query time for the given `rule_name` to its aggregate.
    pub fn query(&mut self, rule_name: &str, elapsed: Duration) {
        Self::increment_aggregate(rule_name, elapsed, &mut self.agg_query_time);
    }

    /// Adds the filename and tree parse duration to the tree-sitter parse time max heap.
    pub fn parse(&mut self, filename: impl Into<String>, elapsed: Duration) {
        self.file_parse_time.insert((elapsed, filename.into()));
        if self.file_parse_time.len() > STATS_MAX_PARSE_TIMES {
            // Remove the smallest element
            self.file_parse_time.pop_first();
        }
    }

    /// Marks that a file timed out for a specific rule.
    pub fn mark_timeout(&mut self, filename: &str, rule_name: &str) {
        Self::push_filename(filename, rule_name, &mut self.execution_timeouts);
    }

    /// Marks that a JavaScript execution error occurred for a specific file/rule.
    pub fn mark_error(&mut self, filename: &str, rule_name: &str) {
        Self::push_filename(filename, rule_name, &mut self.execution_errors);
    }

    fn push_filename(
        filename: &str,
        rule_name: &str,
        target: &mut HashMap<RuleName, Vec<FileName>>,
    ) {
        if let Some(timeouts) = target.get_mut(rule_name) {
            timeouts.push(filename.to_string());
        } else {
            target.insert(rule_name.to_string(), vec![filename.to_string()]);
        }
    }

    fn increment_aggregate(key: &str, elapsed: Duration, target: &mut HashMap<String, Aggregate>) {
        if let Some(stat) = target.get_mut(key) {
            stat.sample_count += 1;
            stat.time += elapsed;
        } else {
            target.insert(
                key.to_string(),
                Aggregate {
                    sample_count: 1,
                    time: elapsed,
                },
            );
        }
    }
}

/// An aggregated statistic
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
struct Aggregate {
    pub sample_count: usize,
    pub time: Duration,
}

impl std::ops::AddAssign for Aggregate {
    fn add_assign(&mut self, rhs: Self) {
        self.sample_count += rhs.sample_count;
        self.time += rhs.time;
    }
}

impl std::ops::AddAssign for AnalysisStatistics {
    fn add_assign(&mut self, rhs: Self) {
        for (key, value) in rhs.agg_execution_time {
            self.agg_execution_time
                .entry(key)
                .and_modify(|existing| *existing += value)
                .or_insert(value);
        }
        for (key, value) in rhs.agg_query_time {
            self.agg_query_time
                .entry(key)
                .and_modify(|existing| *existing += value)
                .or_insert(value);
        }
        for (key, values) in rhs.execution_timeouts {
            self.execution_timeouts
                .entry(key)
                .and_modify(|existing| existing.extend_from_slice(&values))
                .or_insert(values);
        }
        for (key, values) in rhs.execution_errors {
            self.execution_errors
                .entry(key)
                .and_modify(|existing| existing.extend_from_slice(&values))
                .or_insert(values);
        }
        for (duration, filename) in rhs.file_parse_time {
            self.parse(filename, duration);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};
    use std::time::Duration;

    use crate::{Aggregate, AnalysisStatistics, FileName, STATS_MAX_PARSE_TIMES};

    /// Tests that the combining of `AnalysisStatistics` is logically correct
    #[test]
    fn statistics_combine() {
        fn s(str: &str) -> String {
            str.to_string()
        }
        /// A shorthand for building a HashMap entry for `Aggregate`
        fn agg(rule: &str, secs: u64, count: usize) -> (String, Aggregate) {
            let aggregate = Aggregate {
                sample_count: count,
                time: Duration::from_secs(secs),
            };
            (rule.to_string(), aggregate)
        }
        /// A shorthand for building a HashMap entry for a string vec.
        fn files(rule: &str, filenames: &[&str]) -> (String, Vec<FileName>) {
            let filenames = filenames.iter().map(ToString::to_string).collect();
            (rule.to_string(), filenames)
        }

        let stats1 = AnalysisStatistics {
            agg_execution_time: HashMap::from([agg("rs/rule1", 6, 3), agg("rs/rule2", 5, 3)]),
            agg_query_time: HashMap::from([agg("rs/rule1", 2, 3), agg("rs/rule2", 2, 3)]),
            execution_timeouts: HashMap::from([files("rs/rule1", &["file1.js", "file2.js"])]),
            execution_errors: HashMap::from([files("rs/rule2", &["err1.js"])]),
            file_parse_time: BTreeSet::from([
                (Duration::from_secs(1), s("file1.js")),
                (Duration::from_secs(2), s("file2.js")),
                (Duration::from_secs(3), s("err1.js")),
            ]),
        };
        let stats2 = AnalysisStatistics {
            agg_execution_time: HashMap::from([agg("rs/rule1", 10, 2), agg("rs/rule2", 14, 2)]),
            agg_query_time: HashMap::from([agg("rs/rule1", 2, 2), agg("rs/rule2", 1, 2)]),
            execution_timeouts: HashMap::from([files("rs/rule2", &["file3.js"])]),
            execution_errors: HashMap::from([files("rs/rule2", &["err2.js"])]),
            file_parse_time: BTreeSet::from([
                (Duration::from_secs(1), s("file3.js")),
                (Duration::from_secs(3), s("err2.js")),
            ]),
        };
        let expected = AnalysisStatistics {
            agg_execution_time: HashMap::from([agg("rs/rule1", 16, 5), agg("rs/rule2", 19, 5)]),
            agg_query_time: HashMap::from([agg("rs/rule1", 4, 5), agg("rs/rule2", 3, 5)]),
            execution_timeouts: HashMap::from([
                files("rs/rule1", &["file1.js", "file2.js"]),
                files("rs/rule2", &["file3.js"]),
            ]),
            execution_errors: HashMap::from([files("rs/rule2", &["err1.js", "err2.js"])]),
            file_parse_time: BTreeSet::from([
                (Duration::from_secs(1), s("file1.js")),
                (Duration::from_secs(2), s("file2.js")),
                (Duration::from_secs(3), s("err1.js")),
                (Duration::from_secs(1), s("file3.js")),
                (Duration::from_secs(3), s("err2.js")),
            ]),
        };
        // For dev expedience, we don't implement Add, so structure the test to use AddAssign
        let mut test1 = stats1.clone();
        test1 += stats2;
        assert_eq!(test1, expected);
    }

    /// Tests that the `file_parse_time` heap respects the configured max limit.
    #[test]
    fn file_parse_time_stat_limit() {
        let mut stats = AnalysisStatistics::default();
        for i in 0..(STATS_MAX_PARSE_TIMES * 2) {
            let index = i + 1;
            let duration = Duration::from_secs(index as u64);
            stats.parse(format!("file-{}", index), duration)
        }
        assert_eq!(stats.file_parse_time.len(), STATS_MAX_PARSE_TIMES);

        // Min element
        let expected_min = STATS_MAX_PARSE_TIMES + 1;
        let expected_min_str = format!("file-{}", expected_min);
        assert_eq!(
            stats.file_parse_time.iter().next().unwrap(),
            &(Duration::from_secs(expected_min as u64), expected_min_str)
        );
        // Max element
        let expected_max = STATS_MAX_PARSE_TIMES * 2;
        let expected_max_str = format!("file-{}", expected_max);
        assert_eq!(
            stats.file_parse_time.iter().next_back().unwrap(),
            &(Duration::from_secs(expected_max as u64), expected_max_str)
        );
    }
}
