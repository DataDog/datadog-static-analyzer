use anyhow::{Context, Result};
use cli::config_file::read_config_file;
use cli::constants::{DEFAULT_MAX_CPUS, DEFAULT_MAX_FILE_SIZE_KB};
use cli::datadog_utils::{get_all_default_rulesets, get_rules_from_rulesets, get_secrets_rules};
use cli::file_utils::{
    filter_files_by_size, filter_files_for_language, get_files, read_files_from_gitignore,
};
use cli::git_utils::{
    get_changed_files_between_shas, get_changed_files_with_branch, get_default_branch,
};
use cli::model::cli_configuration::CliConfiguration;
use cli::rule_utils::{
    check_rules_checksum, convert_rules_to_rules_internal, get_languages_for_rules,
};
use cli::utils::{choose_cpu_count, get_num_threads_to_use, print_configuration};
use common::analysis_options::AnalysisOptions;
use console::Emoji;
use getopts::Options;
use git2::Repository;
use itertools::Itertools;
use kernel::analysis::analyze::analyze;
use kernel::constants::{CARGO_VERSION, VERSION};
use kernel::model::common::OutputFormat::Json;
use kernel::model::config_file::{ConfigFile, PathConfig};
use kernel::model::rule::{Rule, RuleInternal, RuleResult};
use kernel::rule_config::RuleConfigProvider;
use rayon::prelude::*;
use rocket::yansi::Paint;
use secrets::model::secret_result::SecretResult;
use secrets::scanner::{build_sds_scanner, find_secrets};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::exit;
use std::sync::Arc;
use std::{env, fs, io};

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
        IssueType::Secret => Emoji("🔑", ""),
        IssueType::StaticAnalysis => Emoji("🛑", ""),
    };

    let error_type = match kind {
        IssueType::Secret => "secret",
        IssueType::StaticAnalysis => "code violation",
    };

    let red_str_fmt = format!(
        "{} {} {} found on file {} line {}",
        Emoji("⚠️", "/!\\"),
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
    let mut use_configuration_file = false;
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
    opts.optflag("", "secrets", "enable secrets detection (BETA)");

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

    let secrets_enabled = matches.opt_present("secrets");
    let default_branch_opt = matches.opt_str("default-branch");
    let sha_start_opt = matches.opt_str("sha-start");
    let sha_end_opt = matches.opt_str("sha-end");

    let use_debug = *matches
        .opt_str("d")
        .map(|value| value == "yes" || value == "true")
        .get_or_insert(env::var_os("DD_SA_DEBUG").is_some());

    let mut path_config = PathConfig {
        ignore: Vec::new(),
        only: None,
    };
    let directory_to_analyze_option = matches.opt_str("r");

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
    let rule_config_provider = configuration_file
        .as_ref()
        .map(RuleConfigProvider::from_config)
        .unwrap_or_default();

    // if there is a configuration file, we load the rules from it. But it means
    // we cannot have the rule parameter given.
    if let Some(conf) = configuration_file {
        use_configuration_file = true;
        ignore_gitignore = conf.ignore_gitignore.unwrap_or(false);

        let rulesets = conf.rulesets.keys().cloned().collect_vec();
        let rules_from_api = get_rules_from_rulesets(&rulesets, use_staging, use_debug)
            .context("error when reading rules from API")?;
        rules.extend(rules_from_api);

        // copy the only and ignore paths from the configuration file
        path_config.ignore.extend(conf.paths.ignore);
        path_config.only = conf.paths.only;

        // Get the max file size from the configuration or default to the default constant.
        max_file_size_kb = conf.max_file_size_kb.unwrap_or(DEFAULT_MAX_FILE_SIZE_KB);
        ignore_generated_files = conf.ignore_generated_files.unwrap_or(true);
    } else {
        use_configuration_file = false;
        // if there is no config file, we take the default rules from our APIs.

        if use_debug {
            println!("WARNING: no configuration file detected, getting the default rules from the Datadog API");
            println!("Check the following resources to configure your rules:");
            println!(
                    " - Datadog documentation: https://docs.datadoghq.com/code_analysis/static_analysis"
                );
            println!(" - Static analyzer repository on GitHub: https://github.com/DataDog/datadog-static-analyzer");
        }
        let rulesets_from_api =
            get_all_default_rulesets(use_staging, use_debug).expect("cannot get default rules");

        rules.extend(rulesets_from_api.into_iter().flat_map(|v| v.rules.clone()));
    }

    let secrets_rules = if secrets_enabled {
        get_secrets_rules(use_staging)?
    } else {
        vec![]
    };

    // ignore all directories that are in gitignore
    if !ignore_gitignore {
        let paths_from_gitignore = read_files_from_gitignore(directory_to_analyze.as_str())
            .expect("error when reading gitignore file");
        path_config
            .ignore
            .extend(paths_from_gitignore.iter().map(|p| p.clone().into()));
    }

    let files_in_repository = get_files(directory_to_analyze.as_str(), vec![], &path_config)
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
        source_subdirectories: vec![],
        path_config,
        rules_file: None,
        output_format: Json,
        num_cpus,
        rules: rules.clone(),
        rule_config_provider,
        output_file: "".to_string(),
        max_file_size_kb,
        use_staging,
        show_performance_statistics: false,
        ignore_generated_files,
        secrets_enabled,
        secrets_rules: secrets_rules.clone(),
    };

    if configuration.use_debug {
        print_configuration(&configuration);
    }

    let analysis_options = AnalysisOptions {
        log_output: true,
        use_debug,
        ignore_generated_files,
    };

    if should_verify_checksum {
        if let Err(e) = check_rules_checksum(configuration.rules.as_slice()) {
            eprintln!("error when checking rules checksum: {e}");
            exit(1)
        }
    }

    let num_threads = get_num_threads_to_use(&configuration);

    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()?;

    let files_filtered_by_size = filter_files_by_size(&files_in_repository, &configuration);
    let repository =
        Repository::init(&configuration.source_directory).expect("fail to initialize repository");

    let modifications: HashMap<PathBuf, Vec<u32>> = match (
        &default_branch_opt,
        &sha_start_opt,
        &sha_end_opt,
    ) {
        (Some(_), Some(_), Some(_)) => {
            eprintln!(
                "incompatible options: cannot use --sha-start --sha-end and --default-branch"
            );
            exit(1);
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
                exit(1);
            });

            if configuration.use_debug {
                println!("detected default branch={}", default_branch);
            }

            get_changed_files_with_branch(&repository, &default_branch)?
        }
    };

    let changed_files: Vec<PathBuf> = modifications
        .keys()
        .map(|f| directory_path.join(f))
        .collect();

    if configuration.use_debug {
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

    let files_to_analyze: Vec<PathBuf> = files_filtered_by_size
        .into_iter()
        .filter(|f| changed_files.contains(f))
        .collect();

    if configuration.use_debug {
        println!(
            "files to analyze: {}",
            files_to_analyze
                .iter()
                .map(|f| f.to_str().unwrap_or(""))
                .join(",")
        );
    }

    // static analysis part
    let mut fail_for_static_analysis = false;
    let languages = get_languages_for_rules(&rules);
    let mut all_rule_results: Vec<RuleResult> = vec![];
    for language in &languages {
        let files_for_language = filter_files_for_language(&files_to_analyze, language);

        if files_for_language.is_empty() {
            continue;
        }

        let rules_for_language: Vec<RuleInternal> =
            convert_rules_to_rules_internal(&configuration, language)?;

        // take the relative path for the analysis
        let rule_results: Vec<RuleResult> = files_for_language
            .into_par_iter()
            .flat_map(|path| {
                let relative_path = path
                    .strip_prefix(directory_path)
                    .unwrap()
                    .to_str()
                    .expect("path contains non-Unicode characters");
                let relative_path: Arc<str> = Arc::from(relative_path);
                let rule_config = configuration
                    .rule_config_provider
                    .config_for_file(relative_path.as_ref());
                if let Ok(file_content) = fs::read_to_string(&path) {
                    let file_content = Arc::from(file_content);
                    analyze(
                        language,
                        &rules_for_language,
                        &relative_path,
                        &file_content,
                        &rule_config,
                        &analysis_options,
                    )
                } else {
                    vec![]
                }
            })
            .collect();

        all_rule_results.extend(rule_results);
    }

    for rule_result in all_rule_results {
        let path = PathBuf::from(rule_result.filename);

        for violation in rule_result.violations {
            if let Some(lines) = modifications.get(&path) {
                if lines.contains(&violation.start.line) {
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
                    continue;
                }
            }
        }
    }

    // Secrets detection
    let mut fail_for_secrets = false;

    if secrets_enabled {
        let secrets_files = &files_to_analyze;

        let sds_scanner = build_sds_scanner(&secrets_rules);

        let secrets_results: Vec<SecretResult> = secrets_files
            .par_iter()
            .flat_map(|path| {
                let relative_path = path
                    .strip_prefix(directory_path)
                    .unwrap()
                    .to_str()
                    .expect("path contains non-Unicode characters");
                if let Ok(file_content) = fs::read_to_string(path) {
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
                }
            })
            .collect();

        for secret_result in secrets_results {
            let path = PathBuf::from(secret_result.filename);

            for secret_match in secret_result.matches {
                if let Some(lines) = modifications.get(&path) {
                    if lines.contains(&secret_match.start.line) {
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
                        continue;
                    }
                }
            }
        }
    }

    let failed = fail_for_secrets || fail_for_static_analysis;

    if failed {
        if use_confirmation {
            if user_override() {
                exit(0)
            } else {
                exit(1)
            }
        } else {
            exit(1)
        }
    }
    exit(0)
}
