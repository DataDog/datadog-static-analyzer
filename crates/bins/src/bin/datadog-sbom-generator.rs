use cli::config_file::read_config_file;
use cli::datadog_utils::{
    get_all_default_rulesets, get_diff_aware_information, get_rules_from_rulesets,
};
use cli::file_utils::{
    are_subdirectories_safe, filter_files_by_diff_aware_info, filter_files_by_size,
    filter_files_for_language, get_files, match_extension, read_files_from_gitignore,
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
use cli::secrets::{SecretResult, SecretRule};
use cli::violations_table;
use getopts::Options;
use indicatif::ProgressBar;
use kernel::arguments::ArgumentProvider;
use kernel::model::config_file::{ConfigFile, PathConfig};
use kernel::path_restrictions::PathRestrictions;
use kernel::rule_overrides::RuleOverrides;
use rayon::prelude::*;
use rocket::http::hyper::body::HttpBody;
use sbom::analyzers::analyzer::Analyzer;
use sbom::analyzers::jvm_pom::JvmPom;
use sbom::cyclonedx::generate::generate_sbom;
use sbom::model::dependency::Dependency;
use std::collections::HashMap;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::{Instant, SystemTime};
use std::{env, fs};

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
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
        "c",
        "cpus",
        format!("allow N CPUs at once; if unspecified, defaults to the number of logical cores on the platform or {}, whichever is less", DEFAULT_MAX_CPUS).as_str(),
        "--cpus 5",
    );
    opts.optopt("d", "debug", "use debug mode", "yes/no");
    opts.optopt("o", "output", "output file name", "output.json");
    opts.optflag("h", "help", "print this help");
    opts.optflag("v", "version", "shows the tool version");

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

    if !matches.opt_present("o") {
        eprintln!("output file not specified");
        print_usage(&program, opts);
        exit(1);
    }

    let directory_to_analyze_option = matches.opt_str("i");
    let subdirectories_to_analyze = matches.opt_strs("u");

    if directory_to_analyze_option.is_none() {
        eprintln!("no directory passed, specify a directory with option -i");
        print_usage(&program, opts);
        exit(1)
    }

    let directory_to_analyze = directory_to_analyze_option.unwrap();
    let directory_path = std::path::Path::new(&directory_to_analyze);

    let output_file = matches
        .opt_str("o")
        .context("output file must be specified")?;

    if !directory_path.is_dir() {
        eprintln!("directory to analyze is not correct");
        exit(1)
    }

    if !are_subdirectories_safe(directory_path, &subdirectories_to_analyze) {
        eprintln!("sub-directories are not safe and point outside of the repository");
        exit(1)
    }

    let files_in_repository = get_files(
        directory_to_analyze.as_str(),
        subdirectories_to_analyze.clone(),
        None,
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

    // we always keep one thread free and some room for the management threads that monitor
    // the rule execution.
    let ideal_threads = ((num_cpus as f32 - 1.0) * 0.90) as usize;
    let num_threads = if ideal_threads == 0 { 1 } else { ideal_threads };

    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()?;

    let mut total_files_analyzed: usize = 0;
    let start_timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let analyzers = vec![JvmPom::new()];
    let mut dependencies: Vec<Dependency> = vec![];
    for analyzer in analyzers {
        let files = files_in_repository
            .iter()
            .filter(|f| match_extension(f, &[analyzer.get_file_extension()]));
        for f in files {
            println!("parse {}", f.display());
            dependencies.extend(analyzer.parse_file(f.to_str().unwrap()).unwrap());
        }
    }

    let end_timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let execution_time_secs = end_timestamp - start_timestamp;

    println!(
        "Analyze done, found {} dependencies within {} sec(s)",
        dependencies.len(),
        execution_time_secs
    );

    generate_sbom(dependencies, output_file.as_str());

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
