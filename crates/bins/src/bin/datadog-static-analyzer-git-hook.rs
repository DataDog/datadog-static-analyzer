use anyhow::{Context, Result};
use cli::config_file::{get_config, parse_sast_config, parse_secrets_config, ConfigFileSchema};
use cli::constants::{
    DEFAULT_MAX_CPUS, DEFAULT_MAX_FILE_SIZE_KB, DEFAULT_SECRETS_MAX_FILE_SIZE_KB,
    DEFAULT_TOOL_NAME, EXIT_CODE_GITHOOK_FAILED, EXIT_CODE_INVALID_CONFIGURATION,
    EXIT_CODE_INVALID_DIRECTORY, EXIT_CODE_NO_DIRECTORY, EXIT_CODE_NO_SECRET_OR_STATIC_ANALYSIS,
    EXIT_CODE_RULESET_NOT_FOUND, EXIT_CODE_RULE_CHECKSUM_INVALID, EXIT_CODE_SHA_OR_DEFAULT_BRANCH,
};
use cli::datadog_utils::{
    get_all_default_rulesets, get_rules_from_rulesets, get_secrets_rules, DatadogApiError,
};
use cli::file_utils::{read_files_from_gitignore, select_files, ProductFileSelection};
use cli::git_utils::{
    get_changed_files_between_shas, get_changed_files_with_branch, get_default_branch,
};
use cli::model::run_configuration::RunConfiguration;
use cli::model::sast_configuration::CliConfigurationSast;
use cli::model::sast_configuration::SastConfiguration;
use cli::model::secrets_configuration::CliConfigurationSecrets;
use cli::model::secrets_configuration::SecretsConfiguration;
use cli::rule_utils::{check_rules_checksum, get_languages_for_rules};
use cli::sarif::sarif_utils::{generate_sarif_file, SarifReportMetadata};
use cli::utils::{
    choose_cpu_count, get_num_threads_to_use, print_run_configuration, print_sast_configuration,
    print_secrets_configuration,
};
use common::analysis_options::AnalysisOptions;
use common::model::config_method::ConfigMethod;
use common::model::diff_aware::DiffAware;
use datadog_static_analyzer::{secret_analysis, static_analysis};
use getopts::Options;
use git2::Repository;
use itertools::Itertools;
use kernel::analysis::ddsa_lib::v8_platform::{initialize_v8, Initialized, V8Platform};
use kernel::classifiers::ArtifactClassification;
use kernel::config::common::PathConfig;
use kernel::constants::{CARGO_VERSION, VERSION};
use kernel::model::common::OutputFormat::Json;
use kernel::model::rule::{Rule, RuleResult};
use kernel::rule_config::RuleConfigProvider;
use rocket::yansi::Paint;
use secrets::secret_files::should_ignore_file_for_secret;
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::exit;
use std::time::{Duration, Instant};
use std::{env, fs, io};
use terminal_emoji::Emoji;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    print!("{}", opts.usage(&brief));
}

enum IssueType {
    Secret,
    StaticAnalysis,
}

fn format_error(file: &str, line: u32, rule: &str, kind: IssueType) -> String {
    let error_type_emoji = match kind {
        IssueType::Secret => Emoji::new("🔑", ""),
        IssueType::StaticAnalysis => Emoji::new("🛑", ""),
    };

    let error_type = match kind {
        IssueType::Secret => "secret",
        IssueType::StaticAnalysis => "code violation",
    };

    let red_str_fmt = format!(
        "{} {} {} found on file {} line {}",
        Emoji::new("⚠️", "/!\\"),
        error_type_emoji,
        error_type,
        file,
        line,
    );

    let red_str = red_str_fmt.magenta();

    let rule_str = format!("(type: {})", rule);
    format!("{red_str} {rule_str}")
}

/// Ask the user if they want to continue
/// User enters "yes" -> function returns true
/// User enters "no" -> function returns false
fn user_override() -> bool {
    loop {
        let prompt = "do you want to override the check and continue?".cyan();
        println!("{} {} (yes/no): ", Emoji("⛔️", "WARNING"), prompt);
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("error: unable to read user input");
        let user_input = input.trim();
        if user_input == "yes" {
            return true;
        }
        if user_input == "no" {
            return false;
        }
    }
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
        "r",
        "repository",
        "repository",
        "/path/to/code/to/git/repository",
    );

    opts.optopt("", "default-branch", "default branch", "main");

    opts.optopt(
        "",
        "sha-start",
        "sha start",
        "077a3609dbff7c390efe54820e0bda3536685605",
    );
    opts.optopt(
        "",
        "sha-end",
        "sha end",
        "484df034272a3f63c1796ef44f83a790d7729590",
    );

    opts.optopt(
        "o",
        "output",
        "output file name to write all findings from the Git hooks to (SARIF output)",
        "/tmp/file-output.sarif",
    );

    opts.optopt("d", "debug", "use debug mode", "yes/no");

    opts.optopt(
        "c",
        "cpus",
        format!("allow N CPUs at once; if unspecified, defaults to the number of logical cores on the platform or {}, whichever is less", DEFAULT_MAX_CPUS).as_str(),
        "--cpus 5",
    );

    opts.optflag("h", "help", "print this help");
    opts.optflag("v", "version", "shows the tool version");
    opts.optflag(
        "b",
        "bypass-checksum",
        "bypass checksum verification for the rules",
    );

    opts.optflag("s", "staging", "use staging");
    opts.optflag(
        "",
        "confirmation",
        "user must validate if they want to continue",
    );
    opts.optflag("t", "include-testing-rules", "include testing rules");
    opts.optflag(
        "",
        "secrets",
        "enable secrets detection (DEPRECATED, use enable-secrets)",
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

    let should_verify_checksum = !matches.opt_present("b");
    let use_staging = matches.opt_present("s");
    let use_confirmation = matches.opt_present("confirmation");

    let secrets_enabled_old_option = matches.opt_present("secrets");
    let static_analysis_enabled = matches
        .opt_str("enable-static-analysis")
        .map(|value| value == "true" || value == "yes")
        .unwrap_or(false);
    let secrets_enabled_new_option = matches
        .opt_str("enable-secrets")
        .map(|value| value == "true" || value == "yes")
        .unwrap_or(false);
    let secrets_enabled = secrets_enabled_old_option || secrets_enabled_new_option;
    let default_branch_opt = matches.opt_str("default-branch");
    let sha_start_opt = matches.opt_str("sha-start");
    let sha_end_opt = matches.opt_str("sha-end");
    let output_opt = matches.opt_str("output");

    let use_debug = *matches
        .opt_str("d")
        .map(|value| value == "yes" || value == "true")
        .get_or_insert(env::var_os("DD_SA_DEBUG").is_some());

    let mut path_config = PathConfig {
        ignore: Vec::new(),
        only: None,
    };
    let directory_to_analyze_option = matches.opt_str("r");

    let Some(directory_to_analyze) = directory_to_analyze_option.map(PathBuf::from) else {
        eprintln!("no directory passed, specify a directory with option -i");
        print_usage(&program, opts);
        exit(EXIT_CODE_NO_DIRECTORY)
    };

    if !directory_to_analyze.is_dir() {
        eprintln!("directory to analyze is not correct");
        exit(EXIT_CODE_INVALID_DIRECTORY)
    }

    if !static_analysis_enabled && !secrets_enabled {
        eprintln!("no features (static analysis or secrets) activated");
        eprintln!(
            "either --enable-static-analysis true or --enable-secrets true should be specified"
        );
        print_usage(&program, opts);
        exit(EXIT_CODE_NO_SECRET_OR_STATIC_ANALYSIS)
    }

    let (config_contents, configuration_method): (
        Option<(String, ConfigFileSchema)>,
        Option<ConfigMethod>,
    ) = match get_config(&directory_to_analyze, use_debug) {
        Ok(Some((contents, schema, config_method))) => {
            (Some((contents, schema)), Some(config_method))
        }
        Ok(None) => (None, None),
        Err(err) => {
            eprintln!(
                "Error reading configuration file from {}:\n  {}",
                directory_to_analyze.display(),
                err
            );
            exit(EXIT_CODE_INVALID_CONFIGURATION)
        }
    };

    // Each product reads its own section, and only when it is enabled: an invalid section for a
    // product that isn't running cannot fail the run.
    let sast_config_file = match (&config_contents, static_analysis_enabled) {
        (Some((contents, schema)), true) => {
            parse_sast_config(contents, *schema).unwrap_or_else(|err| {
                eprintln!("Error: invalid SAST configuration: {err}");
                exit(EXIT_CODE_INVALID_CONFIGURATION)
            })
        }
        _ => None,
    };
    let secrets_config_file = match (&config_contents, secrets_enabled) {
        (Some((contents, schema)), true) => {
            parse_secrets_config(contents, *schema).unwrap_or_else(|err| {
                eprintln!("Error: invalid Secrets configuration: {err}");
                exit(EXIT_CODE_INVALID_CONFIGURATION)
            })
        }
        _ => None,
    };
    let sast_config = sast_config_file.as_ref();
    let secrets_config = secrets_config_file.as_ref();

    let mut rules: Vec<Rule> = Vec::new();
    let rule_config_provider = sast_config
        .map(RuleConfigProvider::from_sast_config)
        .unwrap_or_default();

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

        if static_analysis_enabled {
            let explicit_rs = conf.explicit_rulesets().collect::<Vec<_>>();
            let rules_from_api = get_rules_from_rulesets(&explicit_rs, use_staging, use_debug)
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

        // copy the only and ignore paths from the configuration file
        if let Some(pc) = conf.global_config.as_ref().and_then(|g| g.paths.as_ref()) {
            path_config.ignore.extend_from_slice(&pc.ignore);
            path_config.only = pc.only.clone();
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

    if static_analysis_enabled {
        // if there is no config file, we take the default rules from our APIs.

        if sast_config.is_none() && use_debug {
            println!("WARNING: no configuration file detected, getting the default rules from the Datadog API");
            println!("Check the following resources to configure your rules:");
            println!(
                    " - Datadog documentation: https://docs.datadoghq.com/code_analysis/static_analysis"
                );
            println!(" - Static analyzer repository on GitHub: https://github.com/DataDog/datadog-static-analyzer");
        }

        let should_fetch = sast_config.is_none_or(|c| c.use_default_rulesets != Some(false));
        if should_fetch {
            let rulesets_from_api =
                get_all_default_rulesets(use_staging, use_debug, &excluded_rulesets)
                    .context("cannot get default rules")?;
            rules.extend(rulesets_from_api.into_iter().flat_map(|rs| rs.into_rules()));
        }
    }

    let secrets_rules = if secrets_enabled {
        get_secrets_rules(use_staging)?
    } else {
        vec![]
    };

    // Read .gitignore patterns once. Each product's `select_files` call below decides for
    // itself (via `ignore_gitignore`) whether to apply them.
    let gitignore_patterns = read_files_from_gitignore(&directory_to_analyze).unwrap_or_else(|e| {
        eprintln!("Warning: error when reading .gitignore file: {}", e);
        eprintln!("Continuing without .gitignore patterns");
        vec![]
    });

    let num_cores_requested = matches
        .opt_str("c")
        .map(|val| {
            val.parse::<usize>()
                .context("unable to parse `cpus` flag as integer")
        })
        .transpose()?;
    // Select the number of cores to use based on the user's CLI arg (or lack of one)
    let num_cpus = get_num_threads_to_use(choose_cpu_count(num_cores_requested));

    // Build the run/SAST/secrets configuration objects that describe how the CLI should behave.
    let run_config = RunConfiguration {
        use_debug,
        configuration_method,
        source_directory: directory_to_analyze.to_string_lossy().to_string(),
        source_subdirectories: vec![],
        output_format: Json,
        output_file: "".to_string(),
        num_cpus,
        use_staging,
        static_analysis_enabled,
        secrets_enabled,
    };
    let sast_config = SastConfiguration {
        ignore_gitignore,
        path_config: path_config.clone(),
        rules_file: None,
        rules: rules.clone(),
        rule_config_provider,
        max_file_size_kb,
        show_performance_statistics: false,
        ignore_generated_files,
        should_verify_checksum: true,
        debug_java_dfa: false,
    };
    let mut secrets_path_config = PathConfig {
        ignore: Vec::new(),
        only: None,
    };
    if let Some(pc) = secrets_config
        .and_then(|c| c.global_config.as_ref())
        .and_then(|g| g.paths.as_ref())
    {
        secrets_path_config.ignore.extend_from_slice(&pc.ignore);
        secrets_path_config.only = pc.only.clone();
    }
    let secrets_ignore_gitignore = secrets_config
        .and_then(|c| c.global_config.as_ref())
        .and_then(|g| g.use_gitignore.map(|b| !b))
        .unwrap_or(false);
    let secrets_ignore_generated_files = secrets_config
        .and_then(|c| c.global_config.as_ref())
        .and_then(|g| g.ignore_generated_files)
        .unwrap_or(true);
    let secrets_max_file_size_kb = secrets_config
        .and_then(|c| c.global_config.as_ref())
        .and_then(|g| g.max_file_size_kb)
        .unwrap_or(DEFAULT_SECRETS_MAX_FILE_SIZE_KB);
    let secrets_config = SecretsConfiguration {
        ignore_gitignore: secrets_ignore_gitignore,
        ignore_generated_files: secrets_ignore_generated_files,
        path_config: secrets_path_config,
        rules: secrets_rules.clone(),
        max_file_size_kb: secrets_max_file_size_kb,
    };

    let sast_cli_config = CliConfigurationSast {
        run: &run_config,
        sast: &sast_config,
    };
    let secrets_cli_config = CliConfigurationSecrets {
        run: &run_config,
        secrets: &secrets_config,
    };

    if run_config.use_debug {
        print_run_configuration(&run_config);
        if run_config.static_analysis_enabled {
            print_sast_configuration(&sast_config);
        }
        if run_config.secrets_enabled {
            print_secrets_configuration(&secrets_config);
        }
    }

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
        ..Default::default()
    };

    if should_verify_checksum {
        if let Err(e) = check_rules_checksum(sast_config.rules.as_slice()) {
            eprintln!("error when checking rules checksum: {e}");
            exit(EXIT_CODE_RULE_CHECKSUM_INVALID)
        }
    }

    let mut v8: Option<V8Platform<Initialized>> = None;
    if static_analysis_enabled {
        let platform = initialize_v8(run_config.num_cpus as u32);
        _ = v8.insert(platform)
    }

    // This must be called _after_ `initialize_v8` (otherwise, PKU-related segfaults on Linux will occur).
    // Stack size is set explicitly to 64MB for the dd-sds scanner's regex matching depth.
    rayon::ThreadPoolBuilder::new()
        .num_threads(run_config.num_cpus)
        .build_global()?;

    // Each product selects its own files independently, so no product's settings can leak
    // into the other's file list.
    let sast_files: Vec<PathBuf> = if static_analysis_enabled {
        select_files(
            &directory_to_analyze,
            &[],
            &gitignore_patterns,
            &ProductFileSelection {
                ignore_gitignore,
                ignore_generated_files,
                path_config: path_config.clone(),
                max_file_size_kb: Some(max_file_size_kb),
            },
            use_debug,
        )
        .expect("unable to get the list of files to analyze for SAST")
    } else {
        vec![]
    };
    let secrets_files: Vec<PathBuf> = if secrets_enabled {
        select_files(
            &directory_to_analyze,
            &[],
            &gitignore_patterns,
            &ProductFileSelection {
                ignore_gitignore: secrets_config.ignore_gitignore,
                ignore_generated_files: secrets_config.ignore_generated_files,
                path_config: secrets_config.path_config.clone(),
                max_file_size_kb: Some(secrets_config.max_file_size_kb),
            },
            use_debug,
        )
        .expect("unable to get the list of files to analyze for secrets")
    } else {
        vec![]
    };

    let repository =
        Repository::open(&run_config.source_directory).expect("fail to open repository");

    let modifications: HashMap<PathBuf, Vec<u32>> = match (
        &default_branch_opt,
        &sha_start_opt,
        &sha_end_opt,
    ) {
        (Some(_), Some(_), Some(_)) => {
            eprintln!(
                "incompatible options: cannot use --sha-start --sha-end and --default-branch"
            );
            exit(EXIT_CODE_SHA_OR_DEFAULT_BRANCH);
        }
        // user specified the default branch
        (Some(default_branch), None, None) => {
            get_changed_files_with_branch(&repository, default_branch)?
        }
        // user specified the start sha and the end sha
        (None, Some(sha_start), Some(sha_end)) => {
            get_changed_files_between_shas(&repository, sha_start, sha_end)?
        }

        // none of this was submitted, try to guess the default branch
        _ => {
            let default_branch = get_default_branch(&repository).unwrap_or_else(|_| {
                eprintln!(
                    "Cannot find the default branch, use --default-branch to force the default branch"
                );
                exit(EXIT_CODE_SHA_OR_DEFAULT_BRANCH);
            });

            if run_config.use_debug {
                println!("detected default branch={}", default_branch);
            }

            get_changed_files_with_branch(&repository, &default_branch)?
        }
    };

    let changed_files: Vec<PathBuf> = modifications
        .keys()
        .map(|f| directory_to_analyze.join(f))
        .collect();

    if run_config.use_debug {
        if changed_files.is_empty() {
            println!("no changed file");
        } else {
            println!(
                "Changed files: {}",
                changed_files
                    .iter()
                    .map(|f| f.to_str().unwrap_or(""))
                    .join(",")
            )
        }
    }

    let files_to_analyze: Vec<PathBuf> = sast_files
        .into_iter()
        .filter(|f| changed_files.contains(f))
        .collect();

    if run_config.use_debug {
        println!(
            "files to analyze: {}",
            files_to_analyze
                .iter()
                .map(|f| f.to_str().unwrap_or(""))
                .join(",")
        );
    }

    let analysis_start_instant = Instant::now();

    // static analysis part
    let mut fail_for_static_analysis = false;
    let mut all_rule_results: Vec<RuleResult> = vec![];

    let mut all_path_metadata = HashMap::<String, ArtifactClassification>::new();

    if static_analysis_enabled {
        let languages = get_languages_for_rules(&sast_config.rules);
        let execution_result = static_analysis(
            v8.expect("v8 should have been initialized manually"),
            sast_cli_config,
            &analysis_options,
            &files_to_analyze,
            &languages,
        )
        .context("static analysis should have succeeded")?;

        let static_analysis_metadata = &execution_result.metadata;
        all_rule_results = execution_result.rule_results.clone();

        all_rule_results.iter_mut().for_each(|rr| {
            let path = PathBuf::from(&rr.filename);
            rr.violations.retain(|v| {
                if let Some(lines) = modifications.get(&path) {
                    lines.contains(&v.start.line)
                } else {
                    false
                }
            });
        });

        all_path_metadata.extend(static_analysis_metadata.clone());

        for rule_result in &all_rule_results {
            let path = PathBuf::from(&rule_result.filename);
            for violation in &rule_result.violations {
                println!(
                    "{}",
                    format_error(
                        path.display().to_string().as_str(),
                        violation.start.line,
                        &rule_result.rule_name,
                        IssueType::StaticAnalysis,
                    )
                );
                fail_for_static_analysis = true;
            }
        }
    }

    // Secrets detection
    let mut fail_for_secrets = false;
    let mut secrets_results = vec![];
    if secrets_enabled {
        let files_to_analyze: Vec<PathBuf> = secrets_files
            .into_iter()
            .filter(|f| changed_files.contains(f))
            .filter(|f| !should_ignore_file_for_secret(f))
            .collect();

        let execution_result =
            secret_analysis(secrets_cli_config, &analysis_options, &files_to_analyze)
                .context("secrets should execute with success")?;

        for (k, v) in &execution_result.metadata {
            if !all_path_metadata.contains_key(k) {
                all_path_metadata.insert(k.clone(), v.clone());
            }
        }

        secrets_results = execution_result.rule_results;

        secrets_results.iter_mut().for_each(|rr| {
            let path = PathBuf::from(&rr.filename);
            rr.matches.retain(|v| {
                if let Some(lines) = modifications.get(&path) {
                    lines.contains(&v.start.line)
                } else {
                    false
                }
            });
        });

        for secret_result in &secrets_results {
            let path = PathBuf::from(&secret_result.filename);

            for secret_match in &secret_result.matches {
                println!(
                    "{}",
                    format_error(
                        path.display().to_string().as_str(),
                        secret_match.start.line,
                        &secret_result.rule_name,
                        IssueType::Secret,
                    )
                );

                fail_for_secrets = true;
            }
        }
    }

    // Write the results to a SARIF file is necessary
    if let Some(output_file) = output_opt {
        let sarif_content = generate_sarif_file(
            sast_cli_config,
            secrets_cli_config,
            all_rule_results,
            secrets_results,
            Vec::new(),
            SarifReportMetadata {
                add_git_info: false,
                debug: run_config.use_debug,
                config_digest: sast_cli_config.generate_diff_aware_digest(),
                diff_aware_parameters: None,
                execution_time_secs: analysis_start_instant.elapsed().as_secs(),
                tool_name: DEFAULT_TOOL_NAME.to_string(),
                split_runs_by_tool: false,
            },
            &all_path_metadata,
        )
        .expect("cannot generate SARIF results");

        let mut file = fs::File::create(output_file).context("cannot create file")?;
        file.write_all(sarif_content.as_bytes())
            .context("error when writing results")?;
    }

    // Logic to handle if the run failed or not and show the confirmation
    let failed = fail_for_secrets || fail_for_static_analysis;

    if failed {
        if use_confirmation {
            if user_override() {
                exit(0)
            } else {
                exit(EXIT_CODE_GITHOOK_FAILED)
            }
        } else {
            exit(EXIT_CODE_GITHOOK_FAILED)
        }
    }
    exit(0)
}
