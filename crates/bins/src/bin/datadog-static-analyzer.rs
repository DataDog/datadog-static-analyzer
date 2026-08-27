use anyhow::{Context, Result};
use getopts::Options;
use itertools::Itertools;
use std::collections::HashMap;
use std::io::prelude::*;
use std::path::PathBuf;
use std::process::exit;
use std::time::{Duration, Instant};
use std::{env, fs};

use cli::config_file;
use cli::constants::{
    DEFAULT_MAX_CPUS, DEFAULT_MAX_FILE_SIZE_KB, DEFAULT_SECRETS_MAX_FILE_SIZE_KB,
    DEFAULT_TOOL_NAME, EXIT_CODE_FAIL_ON_VIOLATION, EXIT_CODE_INVALID_CONFIGURATION,
    EXIT_CODE_INVALID_DIRECTORY, EXIT_CODE_NO_DIRECTORY, EXIT_CODE_NO_OUTPUT,
    EXIT_CODE_RULESET_NOT_FOUND, EXIT_CODE_RULE_FILE_WITH_CONFIGURATION,
    EXIT_CODE_UNSAFE_SUBDIRECTORIES, SECRETS_HISTORY_TOOL_NAME,
};
use cli::csv;
use cli::datadog_utils::{
    get_all_default_rulesets, get_diff_aware_information, get_rules_from_rulesets,
    get_secrets_rules, DatadogApiError,
};
use cli::file_utils::{
    are_subdirectories_safe, filter_files_by_diff_aware_info, read_files_from_gitignore,
    select_files, ProductFileSelection,
};
use cli::model::datadog_api::DiffAwareData;
use cli::model::run_configuration::RunConfiguration;
use cli::model::sast_configuration::CliConfigurationSast;
use cli::model::sast_configuration::SastConfiguration;
use cli::model::secrets_configuration::CliConfigurationSecrets;
use cli::model::secrets_configuration::SecretsConfiguration;
use cli::rule_utils::{
    convert_secret_result_to_rule_result, count_violations_by_severities, get_languages_for_rules,
    get_rulesets_from_file,
};
use cli::sarif::sarif_utils::{generate_sarif_file, HistoricalSecretResult, SarifReportMetadata};
use cli::utils::{
    choose_cpu_count, get_num_threads_to_use, print_run_configuration, print_sast_configuration,
    print_secrets_configuration,
};
use cli::violations_table;
use common::analysis_options::AnalysisOptions;
use common::model::config_method::ConfigMethod;
use common::model::diff_aware::DiffAware;
use datadog_static_analyzer::{git_history_secret_analysis, secret_analysis, static_analysis};
use kernel::analysis::ddsa_lib::v8_platform::{initialize_v8, Initialized, V8Platform};
use kernel::classifiers::ArtifactClassification;
use kernel::config::common::PathConfig;
use kernel::config::file_v1 as sast_file_v1;
use kernel::constants::{CARGO_VERSION, VERSION};
use kernel::model::common::{Language, OutputFormat};
use kernel::model::rule::{Rule, RuleResult, RuleSeverity};
use kernel::rule_config::RuleConfigProvider;
use secrets::config::file_v1 as secrets_file_v1;
use secrets::model::secret_result::{SecretResult, SecretValidationStatus};
use secrets::secret_files::should_ignore_file_for_secret;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    print!("{}", opts.usage(&brief));
}

struct CliArgs {
    directory_to_analyze: PathBuf,
    subdirectories_to_analyze: Vec<String>,
    rules_file: Option<String>,
    ignore_paths_from_options: Vec<String>,
    output_file: String,
    output_format: OutputFormat,
    use_debug: bool,
    use_staging: bool,
    static_analysis_enabled: bool,
    secrets_enabled: bool,
    scan_git_history_only: bool,
    diff_aware_requested: bool,
    should_verify_checksum: bool,
    add_git_info: bool,
    show_performance_statistics: bool,
    print_violations: bool,
    fail_any_violation_severities: Vec<RuleSeverity>,
    debug_java_dfa: bool,
    num_cpus: usize,
    timeout: Option<Duration>,
}

/// Parse and validate the CLI args. Exits the process directly on invalid or missing arguments.
fn parse_cli_args(raw_args: &[String]) -> Result<CliArgs> {
    let program = raw_args[0].clone();
    let mut opts = Options::new();

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
    opts.optflag(
        "",
        "scan-git-history-only",
        "scan the entire git history for secrets that are not present at the current HEAD. Every \
         commit is scanned (not just what current refs point to); a finding is 'history-only' \
         relative to HEAD, so a secret still live at the tip of another branch, tag, or remote may \
         also be reported as history-only.",
    );

    let matches = match opts.parse(&raw_args[1..]) {
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
    let show_performance_statistics = matches.opt_present("x");
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

    let scan_git_history_only = matches.opt_present("scan-git-history-only");

    // A git-history scan produces a historic-only secrets report, so it is meaningless
    // without secrets enabled. Fail fast rather than silently running a no-op.
    if scan_git_history_only && !secrets_enabled {
        eprintln!("--scan-git-history-only requires secrets scanning; pass --enable-secrets true");
        exit(EXIT_CODE_INVALID_CONFIGURATION);
    }

    let output_file = matches
        .opt_str("o")
        .context("output file must be specified")?;

    let ignore_paths_from_options = matches.opt_strs("p");
    let directory_to_analyze_option = matches.opt_str("i");
    let subdirectories_to_analyze = matches.opt_strs("u");

    let rules_file = matches.opt_str("r");

    let Some(directory_to_analyze) = directory_to_analyze_option.map(PathBuf::from) else {
        eprintln!("no directory passed, specify a directory with option -i");
        print_usage(&program, opts);
        exit(EXIT_CODE_NO_DIRECTORY)
    };

    if !directory_to_analyze.is_dir() {
        eprintln!("directory to analyze is not correct");
        exit(EXIT_CODE_INVALID_DIRECTORY)
    }

    if !are_subdirectories_safe(&directory_to_analyze, &subdirectories_to_analyze) {
        eprintln!("sub-directories are not safe and point outside of the repository");
        exit(EXIT_CODE_UNSAFE_SUBDIRECTORIES)
    }

    let num_cores_requested = matches
        .opt_str("c")
        .map(|val| {
            val.parse::<usize>()
                .context("unable to parse `cpus` flag as integer")
        })
        .transpose()?;
    let num_cpus = choose_cpu_count(num_cores_requested);

    let timeout = matches
        .opt_str("rule-timeout-ms")
        .map(|val| {
            val.parse::<u64>()
                .map(Duration::from_millis)
                .context("unable to parse `rule-timeout-ms` flag as integer")
        })
        .transpose()?;

    Ok(CliArgs {
        directory_to_analyze,
        subdirectories_to_analyze,
        rules_file,
        ignore_paths_from_options,
        output_file,
        output_format,
        use_debug,
        use_staging,
        static_analysis_enabled,
        secrets_enabled,
        scan_git_history_only,
        diff_aware_requested,
        should_verify_checksum,
        add_git_info,
        show_performance_statistics,
        print_violations,
        fail_any_violation_severities,
        debug_java_dfa,
        num_cpus,
        timeout,
    })
}

/// Resolve SAST's own configuration: rules (from a config file, a rules file, or the default
/// remote rulesets) and its own settings.
fn resolve_sast_config(
    sast_config: Option<&sast_file_v1::SastConfig>,
    args: &CliArgs,
) -> Result<SastConfiguration> {
    if sast_config.is_none() && args.use_debug {
        eprintln!("INFO: no configuration detected locally or remotely")
    }

    let rule_config_provider = sast_config
        .map(RuleConfigProvider::from_sast_config)
        .unwrap_or_default();

    let mut rules: Vec<Rule> = Vec::new();
    let mut ignore_gitignore = false;
    let mut max_file_size_kb = DEFAULT_MAX_FILE_SIZE_KB;
    let mut ignore_generated_files = true;

    // Rulesets to exclude when fetching default rulesets
    let mut excluded_rulesets = Vec::<&str>::new();
    // if there is a configuration file, we load the rules from it. But it means
    // we cannot have the rule parameter given.
    if let Some(conf) = sast_config {
        ignore_gitignore = conf
            .global_config
            .as_ref()
            .and_then(|g| g.use_gitignore.map(|b| !b))
            .unwrap_or(false);
        if args.rules_file.is_some() {
            eprintln!("a rule file cannot be specified when a configuration file is present.");
            exit(EXIT_CODE_RULE_FILE_WITH_CONFIGURATION);
        }

        if args.static_analysis_enabled {
            let explicit_rs = conf.explicit_rulesets().collect::<Vec<_>>();
            let rules_from_api =
                get_rules_from_rulesets(&explicit_rs, args.use_staging, args.use_debug)
                    .inspect_err(|e| {
                        if let DatadogApiError::RulesetNotFound(rs) = e {
                            eprintln!("Error: ruleset {rs} not found");
                            exit(EXIT_CODE_RULESET_NOT_FOUND);
                        }
                    })
                    .context("error when reading rules from API")?;
            rules.extend(rules_from_api);
            excluded_rulesets.extend(explicit_rs);
            excluded_rulesets.extend(conf.ignore_rulesets.iter().map(String::as_str));
        }
        // Get the max file size from the configuration or default to the default constant.
        max_file_size_kb = conf
            .global_config
            .as_ref()
            .and_then(|g| g.max_file_size_kb)
            .unwrap_or(DEFAULT_MAX_FILE_SIZE_KB);
        ignore_generated_files = conf
            .global_config
            .as_ref()
            .and_then(|g| g.ignore_generated_files)
            .unwrap_or(true);
    }

    if args.static_analysis_enabled {
        // if there is no config file, we take the default rules from our APIs.
        if args.rules_file.is_none() {
            if sast_config.is_none() {
                println!("WARNING: no SAST configuration detected, getting the default rules from the Datadog API");
                println!("Check the following resources to configure your rules:");
                println!(
                    " - Datadog documentation: https://docs.datadoghq.com/code_analysis/static_analysis"
                );
                println!(" - Static analyzer repository on GitHub: https://github.com/DataDog/datadog-static-analyzer");
            }

            let should_fetch = sast_config.is_none_or(|c| c.use_default_rulesets != Some(false));
            if should_fetch {
                let rulesets_from_api =
                    get_all_default_rulesets(args.use_staging, args.use_debug, &excluded_rulesets)
                        .context("cannot get default rules")?;
                rules.extend(rulesets_from_api.into_iter().flat_map(|rs| rs.into_rules()));
            }
        } else {
            let rulesets_from_file =
                get_rulesets_from_file(args.rules_file.clone().unwrap().as_str());
            rules.extend(
                rulesets_from_file
                    .context("cannot read ruleset from file")?
                    .into_iter()
                    .flat_map(|rs| rs.into_rules()),
            );
        }
    }

    // Build SAST's own PathConfig from SAST's own settings only, so secrets' configuration can
    // never silently affect it (and vice-versa).
    let mut sast_path_config = PathConfig {
        ignore: Vec::new(),
        only: None,
    };
    if let Some(pc) = sast_config
        .and_then(|c| c.global_config.as_ref())
        .and_then(|g| g.paths.as_ref())
    {
        sast_path_config.ignore.extend_from_slice(&pc.ignore);
        sast_path_config.only = pc.only.clone();
    }
    sast_path_config.ignore.extend(
        args.ignore_paths_from_options
            .iter()
            .map(|p| p.clone().into()),
    );

    Ok(SastConfiguration {
        ignore_gitignore,
        path_config: sast_path_config,
        rules_file: args.rules_file.clone(),
        rules,
        rule_config_provider,
        max_file_size_kb,
        show_performance_statistics: args.show_performance_statistics,
        ignore_generated_files,
        should_verify_checksum: args.should_verify_checksum,
        debug_java_dfa: args.debug_java_dfa,
    })
}

/// Resolve secrets' own configuration.
fn resolve_secrets_config(
    secrets_config: Option<&secrets_file_v1::SecretsConfig>,
    args: &CliArgs,
) -> Result<SecretsConfiguration> {
    let rules = if args.secrets_enabled {
        get_secrets_rules(args.use_staging)?
    } else {
        vec![]
    };

    let mut path_config = PathConfig {
        ignore: Vec::new(),
        only: None,
    };
    if let Some(pc) = secrets_config
        .and_then(|c| c.global_config.as_ref())
        .and_then(|g| g.paths.as_ref())
    {
        path_config.ignore.extend_from_slice(&pc.ignore);
        path_config.only = pc.only.clone();
    }
    path_config.ignore.extend(
        args.ignore_paths_from_options
            .iter()
            .map(|p| p.clone().into()),
    );

    let ignore_gitignore = secrets_config
        .and_then(|c| c.global_config.as_ref())
        .and_then(|g| g.use_gitignore.map(|b| !b))
        .unwrap_or(false);
    let ignore_generated_files = secrets_config
        .and_then(|c| c.global_config.as_ref())
        .and_then(|g| g.ignore_generated_files)
        .unwrap_or(true);
    let max_file_size_kb = secrets_config
        .and_then(|c| c.global_config.as_ref())
        .and_then(|g| g.max_file_size_kb)
        .unwrap_or(DEFAULT_SECRETS_MAX_FILE_SIZE_KB);

    Ok(SecretsConfiguration {
        ignore_gitignore,
        ignore_generated_files,
        path_config,
        rules,
        max_file_size_kb,
    })
}

fn select_sast_files(
    args: &CliArgs,
    sast_config: &SastConfiguration,
    gitignore_patterns: &[String],
) -> Result<Vec<PathBuf>> {
    if !args.static_analysis_enabled {
        return Ok(vec![]);
    }
    select_files(
        &args.directory_to_analyze,
        &args.subdirectories_to_analyze,
        gitignore_patterns,
        &ProductFileSelection {
            ignore_gitignore: sast_config.ignore_gitignore,
            ignore_generated_files: sast_config.ignore_generated_files,
            path_config: sast_config.path_config.clone(),
            max_file_size_kb: Some(sast_config.max_file_size_kb),
        },
        args.use_debug,
    )
    .context("unable to get the list of files to analyze for SAST")
}

fn select_secrets_files(
    args: &CliArgs,
    secrets_config: &SecretsConfiguration,
    gitignore_patterns: &[String],
) -> Result<Vec<PathBuf>> {
    if !args.secrets_enabled {
        return Ok(vec![]);
    }
    select_files(
        &args.directory_to_analyze,
        &args.subdirectories_to_analyze,
        gitignore_patterns,
        &ProductFileSelection {
            ignore_gitignore: secrets_config.ignore_gitignore,
            ignore_generated_files: secrets_config.ignore_generated_files,
            path_config: secrets_config.path_config.clone(),
            max_file_size_kb: Some(secrets_config.max_file_size_kb),
        },
        args.use_debug,
    )
    .context("unable to get the list of files to analyze for secrets")
}

/// Attempt to resolve diff-aware scanning parameters. Diff-aware only ever narrows SAST's file
/// list. Secrets always scans its full/head file set regardless of this.
fn resolve_diff_aware(
    args: &CliArgs,
    cli_config: CliConfigurationSast<'_>,
    sast_files: &[PathBuf],
) -> Option<DiffAwareData> {
    if !args.diff_aware_requested {
        return None;
    }
    let run_config = cli_config.run;

    match cli_config.generate_diff_aware_request_data(run_config.use_debug) {
        Ok(params) => {
            if run_config.use_debug {
                println!(
                    "Diff-aware request with sha {}, branch {}, config hash {}",
                    params.sha, params.branch, params.config_hash
                );
            }

            match get_diff_aware_information(&params, run_config.use_debug) {
                Ok(d) => {
                    if run_config.use_debug {
                        println!(
                            "diff aware enabled, base sha: {}, files to scan {}",
                            d.base_sha,
                            d.files.join(",")
                        );
                    } else if run_config.static_analysis_enabled {
                        println!(
                            "diff-aware enabled, based sha {}, scanning only {}/{} files",
                            d.base_sha,
                            d.files.len(),
                            sast_files.len()
                        )
                    }
                    Some(d)
                }
                Err(e) => {
                    eprintln!("diff aware not enabled (error when receiving diff-aware data from Datadog with config hash {}, sha {}), proceeding with full scan.", &params.config_hash, &params.sha);
                    if run_config.use_debug {
                        eprintln!("error when trying to enabled diff-aware scanning: {:?}", e);
                    }

                    None
                }
            }
        }
        Err(e) => {
            eprintln!("diff aware not enabled (unable to generate diff-aware request data), proceeding with full scan.");
            eprintln!("Make sure the user running the scan owns the repository (use git config --global --add safe.directory <repo-path> if needed)");
            eprintln!(
                "You can run the analyzer with --debug true to get more details about the error"
            );
            eprintln!("Proceeding with full scan");

            if run_config.use_debug {
                eprintln!("error when trying to enabled diff-aware scanning: {:?}", e);
            }

            None
        }
    }
}

/// The outcome of a SAST run: violations plus the path classification metadata gathered along
/// the way.
struct SastRunSummary {
    rule_results: Vec<RuleResult>,
    path_metadata: HashMap<String, ArtifactClassification>,
}

fn run_sast(
    v8: V8Platform<Initialized>,
    cli_config: CliConfigurationSast<'_>,
    options: &AnalysisOptions,
    files_to_analyze: &[PathBuf],
    languages: &[Language],
) -> Result<SastRunSummary> {
    let static_analysis_start = Instant::now();
    let sast_config = cli_config.sast;

    let execution_result = static_analysis(v8, cli_config, options, files_to_analyze, languages)
        .context("static_analysis should have succeeded")?;

    let rules_results = &execution_result.rule_results;

    let nb_violations: u32 = rules_results
        .iter()
        .map(|x| x.violations.iter().filter(|v| !v.is_suppressed).count() as u32)
        .sum();

    let files_with_violations = rules_results
        .iter()
        .unique_by(|v| v.filename.as_str())
        .count();

    let rules_with_matches = rules_results
        .iter()
        .unique_by(|v| v.rule_name.as_str())
        .count();

    let sa_duration = static_analysis_start.elapsed().as_secs_f64();

    println!("Static Analysis Summary");
    println!("  Files scanned: {}", files_to_analyze.len());
    println!("  Files with violations: {}", files_with_violations);
    println!("  Total violations: {}", nb_violations);
    println!("  Rules evaluated: {}", sast_config.rules.len());
    println!("  Rules with matches: {}", rules_with_matches);
    println!("  Duration: {:.3}s", sa_duration);

    Ok(SastRunSummary {
        rule_results: execution_result.rule_results,
        path_metadata: execution_result.metadata,
    })
}

/// The outcome of a secrets run: findings plus the path classification metadata gathered along
/// the way.
struct SecretsRunSummary {
    rule_results: Vec<SecretResult>,
    path_metadata: HashMap<String, ArtifactClassification>,
}

/// Run HEAD secrets scanning.
fn run_secrets(
    cli_config: CliConfigurationSecrets<'_>,
    options: &AnalysisOptions,
    files_raw: Vec<PathBuf>,
) -> Result<SecretsRunSummary> {
    let secrets_start = Instant::now();
    let secrets_config = cli_config.secrets;

    let secrets_files: Vec<PathBuf> = files_raw
        .into_iter()
        .filter(|f| !should_ignore_file_for_secret(f))
        .collect();

    let execution_results = secret_analysis(cli_config, options, &secrets_files)
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

    let files_with_secrets = secrets_rules_results
        .iter()
        .unique_by(|v| v.filename.as_str())
        .count();

    let rules_with_matches = secrets_rules_results
        .iter()
        .unique_by(|v| v.rule_name.as_str())
        .count();

    let secrets_duration = secrets_start.elapsed().as_secs_f64();

    println!("Secrets Summary");
    println!("  Files scanned: {}", secrets_files.len());
    println!("  Files with secrets: {}", files_with_secrets);
    println!("  Total secrets: {}", nb_secrets_found);
    println!("  Valid secrets: {}", nb_secrets_validated);
    println!("  Rules evaluated: {}", secrets_config.rules.len());
    println!("  Rules with matches: {}", rules_with_matches);
    println!("  Duration: {:.3}s", secrets_duration);

    Ok(SecretsRunSummary {
        rule_results: execution_results.rule_results,
        path_metadata: execution_results.metadata,
    })
}

fn run_git_history_secrets(
    cli_config: CliConfigurationSecrets<'_>,
    options: &AnalysisOptions,
) -> Result<Vec<HistoricalSecretResult>> {
    let history_start = Instant::now();
    let historic_secrets = git_history_secret_analysis(cli_config, options)
        .context("git history secret analysis failed")?;

    let history_duration = history_start.elapsed().as_secs_f64();
    println!("Git History Secrets Summary");
    println!("  Historical secrets found: {}", historic_secrets.len());
    println!("  Duration: {:.3}s", history_duration);

    Ok(historic_secrets)
}

/// Serialize the final report (CSV, JSON, or SARIF) from every product's results.
#[allow(clippy::too_many_arguments)]
fn build_report(
    args: &CliArgs,
    sast_cli_config: CliConfigurationSast<'_>,
    secrets_cli_config: CliConfigurationSecrets<'_>,
    static_analysis_rule_results: Vec<RuleResult>,
    secrets_violations: Vec<SecretResult>,
    historic_secrets: Vec<HistoricalSecretResult>,
    diff_aware_parameters: Option<DiffAwareData>,
    global_execution_time_secs: u64,
    all_path_metadata: &HashMap<String, ArtifactClassification>,
) -> String {
    // Both bundles borrow the same run configuration.
    let run_config = sast_cli_config.run;
    // Historic findings carry their commit provenance in `historic_secrets` (consumed by the SARIF
    // output). For JSON/CSV, surface their base results alongside any HEAD secrets. HEAD and
    // historic scans are mutually exclusive, so at most one of the two is non-empty.
    let secrets_for_text_output: Vec<SecretResult> = secrets_violations
        .iter()
        .cloned()
        .chain(historic_secrets.iter().map(|h| h.inner.clone()))
        .collect();

    let nb_total_static_analysis_violations: usize = static_analysis_rule_results
        .iter()
        .map(|x| x.violations.len())
        .sum();

    if args.print_violations && nb_total_static_analysis_violations > 0 {
        violations_table::print_violations_table(&static_analysis_rule_results);
    }

    match run_config.output_format {
        OutputFormat::Csv => {
            csv::generate_csv_results(&static_analysis_rule_results, &secrets_for_text_output)
        }
        OutputFormat::Json => {
            // make sure suppressed results are not included
            let filtered_static: Vec<RuleResult> = static_analysis_rule_results
                .clone()
                .into_iter()
                .map(|mut r| {
                    r.violations.retain(|v| !v.is_suppressed);
                    r
                })
                .collect();
            let filtered_secrets: Vec<RuleResult> = secrets_for_text_output
                .iter()
                .map(convert_secret_result_to_rule_result)
                .map(|mut r| {
                    r.violations.retain(|v| !v.is_suppressed);
                    r
                })
                .collect();
            let combined_results = [filtered_secrets, filtered_static].concat();
            serde_json::to_string(&combined_results).expect("error when getting the JSON report")
        }
        OutputFormat::Sarif => generate_sarif_file(
            sast_cli_config,
            secrets_cli_config,
            static_analysis_rule_results,
            secrets_violations,
            historic_secrets,
            SarifReportMetadata {
                add_git_info: args.add_git_info,
                debug: run_config.use_debug,
                config_digest: sast_cli_config.generate_diff_aware_digest(),
                diff_aware_parameters,
                execution_time_secs: global_execution_time_secs,
                tool_name: if args.scan_git_history_only {
                    SECRETS_HISTORY_TOOL_NAME.to_string()
                } else {
                    DEFAULT_TOOL_NAME.to_string()
                },
                split_runs_by_tool: args.scan_git_history_only,
            },
            all_path_metadata,
        )
        .expect("cannot generate SARIF results"),
    }
}

/// If `--fail-on-any-violation` matched at least one violation, the process exit code to use.
fn decide_exit_code(
    static_results: &[RuleResult],
    fail_any_violation_severities: &[RuleSeverity],
) -> Option<i32> {
    let fail_on_violations = !fail_any_violation_severities.is_empty()
        && count_violations_by_severities(static_results, fail_any_violation_severities, true) > 0;
    fail_on_violations.then_some(EXIT_CODE_FAIL_ON_VIOLATION)
}

fn main() -> Result<()> {
    let raw_args: Vec<String> = env::args().collect();
    let args = parse_cli_args(&raw_args)?;

    // Each product's configuration is only read when that product runs, so a configuration one
    // product cannot use never fails a run of the other.
    let (sast_config_file, sast_config_method): (
        Option<sast_file_v1::ConfigFile>,
        Option<ConfigMethod>,
    ) = if args.static_analysis_enabled {
        match config_file::sast::get_config(&args.directory_to_analyze, args.use_debug) {
            Ok(Some((config_file, config_method))) => (Some(config_file), Some(config_method)),
            Ok(None) => (None, None),
            Err(err) => {
                eprintln!(
                    "Error reading configuration file from {}:\n  {}",
                    args.directory_to_analyze.display(),
                    err
                );
                exit(EXIT_CODE_INVALID_CONFIGURATION)
            }
        }
    } else {
        (None, None)
    };
    let sast_config =
        resolve_sast_config(sast_config_file.as_ref().and_then(|cfg| cfg.sast()), &args)?;

    let (secrets_config_file, secrets_config_method): (
        Option<secrets_file_v1::ConfigFile>,
        Option<ConfigMethod>,
    ) = if args.secrets_enabled {
        match config_file::secrets::get_config(&args.directory_to_analyze, args.use_debug) {
            Ok(Some((config_file, config_method))) => (Some(config_file), Some(config_method)),
            Ok(None) => (None, None),
            Err(err) => {
                eprintln!(
                    "Error reading configuration file from {}:\n  {}",
                    args.directory_to_analyze.display(),
                    err
                );
                exit(EXIT_CODE_INVALID_CONFIGURATION)
            }
        }
    } else {
        (None, None)
    };
    let secrets_config = resolve_secrets_config(
        secrets_config_file.as_ref().and_then(|cfg| cfg.secrets()),
        &args,
    )?;

    let run_config = RunConfiguration {
        use_debug: args.use_debug,
        configuration_method: sast_config_method.or(secrets_config_method),
        source_directory: args.directory_to_analyze.to_string_lossy().to_string(),
        source_subdirectories: args.subdirectories_to_analyze.clone(),
        output_format: args.output_format.clone(),
        output_file: args.output_file.clone(),
        num_cpus: get_num_threads_to_use(args.num_cpus),
        use_staging: args.use_staging,
        static_analysis_enabled: args.static_analysis_enabled,
        secrets_enabled: args.secrets_enabled,
    };

    print_run_configuration(&run_config);
    if run_config.static_analysis_enabled {
        print_sast_configuration(&sast_config);
    }
    if run_config.secrets_enabled {
        print_secrets_configuration(&secrets_config);
    }

    let analysis_options = AnalysisOptions {
        log_output: true,
        use_debug: run_config.use_debug,
        ignore_generated_files: sast_config.ignore_generated_files,
        timeout: args.timeout,
        ..Default::default()
    };

    let gitignore_patterns =
        read_files_from_gitignore(&args.directory_to_analyze).unwrap_or_else(|e| {
            eprintln!("Warning: error when reading .gitignore file: {}", e);
            eprintln!("Continuing without .gitignore patterns");
            vec![]
        });

    let languages = get_languages_for_rules(&sast_config.rules);

    let sast_files = select_sast_files(&args, &sast_config, &gitignore_patterns)?;
    let secrets_files = select_secrets_files(&args, &secrets_config, &gitignore_patterns)?;

    let sast_cli_config = CliConfigurationSast {
        run: &run_config,
        sast: &sast_config,
    };
    let secrets_cli_config = CliConfigurationSecrets {
        run: &run_config,
        secrets: &secrets_config,
    };

    // check if we do a diff-aware scan
    let diff_aware_parameters = resolve_diff_aware(&args, sast_cli_config, &sast_files);

    if run_config.use_debug {
        println!("diff aware data: {:?}", diff_aware_parameters);
    }

    let mut v8: Option<V8Platform<Initialized>> = None;
    if run_config.static_analysis_enabled {
        let platform = initialize_v8(run_config.num_cpus as u32);
        _ = v8.insert(platform)
    }

    // This must be called _after_ `initialize_v8` (otherwise, PKU-related segfaults on Linux will occur).
    // When secrets scanning is enabled, set the stack size to 64MB to accommodate the dd-sds
    // scanner's regex matching depth.
    let mut thread_pool_builder = rayon::ThreadPoolBuilder::new().num_threads(run_config.num_cpus);
    if run_config.secrets_enabled {
        thread_pool_builder = thread_pool_builder.stack_size(64 * 1024 * 1024);
    }
    thread_pool_builder.build_global()?;

    // if diff-aware is enabled, we filter the files and keep only the files we want to analyze from diff-aware
    let files_to_analyze = match &diff_aware_parameters {
        Some(dap) => filter_files_by_diff_aware_info(&sast_files, &args.directory_to_analyze, dap),
        None => sast_files,
    };

    if run_config.use_debug && diff_aware_parameters.is_some() {
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

    let static_analysis_rule_results = if run_config.static_analysis_enabled {
        let summary = run_sast(
            v8.expect("v8 should have been initialized manually"),
            sast_cli_config,
            &analysis_options,
            &files_to_analyze,
            &languages,
        )?;
        all_path_metadata.extend(summary.path_metadata);
        summary.rule_results
    } else {
        vec![]
    };

    // HEAD secrets detection is skipped entirely for a git-history scan.
    let secrets_violations = if run_config.secrets_enabled && !args.scan_git_history_only {
        let summary = run_secrets(secrets_cli_config, &analysis_options, secrets_files)?;
        for (k, v) in summary.path_metadata {
            all_path_metadata.entry(k).or_insert(v);
        }
        summary.rule_results
    } else {
        vec![]
    };

    // Git history scanning.
    //
    // When `--scan-git-history-only` is set, the secrets results are replaced with the
    // historical findings (the HEAD secret scan is skipped above). Static analysis is an
    // independent product and is left untouched.
    let historic_secrets = if args.scan_git_history_only {
        run_git_history_secrets(secrets_cli_config, &analysis_options)?
    } else {
        vec![]
    };

    let global_execution_time_secs = global_start_time.elapsed().as_secs();

    let exit_code = decide_exit_code(
        &static_analysis_rule_results,
        &args.fail_any_violation_severities,
    );

    let value = build_report(
        &args,
        sast_cli_config,
        secrets_cli_config,
        static_analysis_rule_results,
        secrets_violations,
        historic_secrets,
        diff_aware_parameters,
        global_execution_time_secs,
        &all_path_metadata,
    );

    // write the reports
    let mut file = fs::File::create(&run_config.output_file).context("cannot create file")?;
    file.write_all(value.as_bytes())
        .context("error when writing results")?;

    if let Some(code) = exit_code {
        exit(code);
    }

    Ok(())
}
