use cli::config_file::read_config_file;
use cli::datadog_utils::get_rules_from_rulesets;
use cli::file_utils::{filter_files_for_language, get_files};
use cli::model::config_file::ConfigFile;
use cli::rule_utils::{get_languages_for_rules, get_rulesets_from_file};
use cli::sarif_utils::generate_sarif_report;
use kernel::analysis::analyze::analyze;
use kernel::model::analysis::AnalysisOptions;
use kernel::model::common::Language;
use kernel::model::rule::{Rule, RuleInternal};

use anyhow::{Context, Result};
use getopts::Options;
use rayon::prelude::*;
use std::io::prelude::*;
use std::process::exit;
use std::{env, fs};

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    print!("{}", opts.usage(&brief));
}

enum OutputFormat {
    Sarif,
    Json,
}

#[allow(clippy::too_many_arguments)]
fn print_configuration(
    use_debug: bool,
    use_configuration_file: bool,
    source_directory: &str,
    ignore_paths: &[String],
    output_file: &String,
    rules: &Vec<Rule>,
    languages: &[Language],
    output_format: &OutputFormat,
) {
    let configuration_method = if use_configuration_file {
        "config file (static-analysis.datadog.[yml|yaml])"
    } else {
        "rule file"
    };

    let output_format_str = match output_format {
        OutputFormat::Sarif => "sarif",
        OutputFormat::Json => "json",
    };

    let languages_string: Vec<String> = languages.iter().map(|l| l.to_string()).collect();
    println!("Configuration");
    println!("=============");
    println!("config method    : {}", configuration_method);
    println!("#cores           : {}", num_cpus::get());
    println!("#rules loaded    : {}", rules.len());
    println!("source directory : {}", source_directory);
    println!("output file      : {}", output_file);
    println!("output format    : {}", output_format_str);
    println!("ignore paths     : {}", ignore_paths.join(","));
    println!("use config file  : {}", use_configuration_file);
    println!("use debug        : {}", use_debug);
    println!("rules languages  : {}", languages_string.join(","));
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    #[allow(unused_assignments)]
    let mut use_configuration_file = false;
    opts.optopt(
        "i",
        "directory",
        "directory to scan (valid existing directory)",
        "/path/to/code/to/analyze",
    );
    opts.optopt(
        "r",
        "rules",
        "rules to use (json file)",
        "/path/to/rules.json",
    );
    opts.optopt("d", "debug", "use debug mode", "yes/no");
    opts.optopt("f", "format", "format", "json/sarif");
    opts.optopt("o", "output", "output file", "output.json");
    opts.optmulti("p", "ignore-path", "path to ignore", "**/test*.py");
    opts.optflag("h", "help", "print this help");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            panic!("error when parsing arguments: {}", f)
        }
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        exit(1);
    }

    if !matches.opt_present("o") {
        eprintln!("output file not specified");
        print_usage(&program, opts);
        exit(1);
    }

    let output_format = match matches.opt_str("f") {
        Some(f) => {
            if f == "sarif" {
                OutputFormat::Sarif
            } else {
                OutputFormat::Json
            }
        }
        None => OutputFormat::Json,
    };

    let use_debug = *matches
        .opt_str("d")
        .map(|value| value == "yes")
        .get_or_insert(false);
    let output_file = matches
        .opt_str("o")
        .context("output file must be specified")?;

    // Show the ignore paths
    let mut ignore_paths: Vec<String> = Vec::new();
    let ignore_paths_from_options = matches.opt_strs("p");
    let directory_to_analyze_option = matches.opt_str("i");

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

    let configuration_file: Option<ConfigFile> =
        read_config_file(directory_to_analyze.as_str()).unwrap();
    let mut rules: Vec<Rule> = Vec::new();

    // if there is a configuration file, we load the rules from it. But it means
    // we cannot have the rule parameter given.
    if let Some(conf) = configuration_file {
        use_configuration_file = true;
        if rules_file.is_some() {
            eprintln!("a rule file cannot be specified when a configuration file is present.");
            exit(1);
        }

        let rules_from_api = get_rules_from_rulesets(&conf.rulesets);
        rules.extend(rules_from_api.context("error when reading rules from API")?);

        // copy the ignore paths from the configuration file
        if let Some(v) = conf.ignore_paths {
            ignore_paths.extend(v);
        }
    } else {
        use_configuration_file = false;
        // if there is no config file, we must read the rules from a file.
        // Otherwise, we exit.
        if rules_file.is_none() {
            eprintln!("no configuration and no rule files specified. Please have a static-analysis.datadog.yml file or specify rules with -r");
            print_usage(&program, opts);
            exit(1);
        }

        let rulesets_from_file = get_rulesets_from_file(rules_file.unwrap().as_str());
        let rules_from_file: Vec<Rule> = rulesets_from_file
            .context("cannot read ruleset")?
            .iter()
            .flat_map(|v| v.rules.clone())
            .collect();
        rules.extend(rules_from_file);
    }

    ignore_paths.extend(ignore_paths_from_options);

    let languages = get_languages_for_rules(&rules);

    let files_to_analyze = get_files(directory_to_analyze.as_str(), ignore_paths.clone())
        .expect("unable to get the list of files to analyze");

    print_configuration(
        use_debug,
        use_configuration_file,
        &directory_to_analyze,
        &ignore_paths,
        &output_file,
        &rules,
        &languages,
        &output_format,
    );

    let mut all_rule_results = vec![];

    let analysis_options = AnalysisOptions {
        log_output: true,
        use_debug,
    };

    // we always keep one thread free and some room for the management threads that monitor
    // the rule execution.
    let ideal_threads = ((num_cpus::get() as f32 - 1.0) * 0.90) as usize;
    let num_threads = if ideal_threads == 0 { 1 } else { ideal_threads };
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()?;

    for language in &languages {
        let files_for_language = filter_files_for_language(&files_to_analyze, language);

        let rules_for_language: Vec<RuleInternal> = rules
            .iter()
            .filter(|r| r.language == *language)
            .map(|r| {
                r.to_rule_internal()
                    .context("cannot convert to rule internal")
            })
            .collect::<Result<Vec<_>>>()?;

        if use_debug {
            println!(
                "Analyzing {}, {} files detected",
                language,
                files_for_language.len()
            )
        }

        // take the relative path for the analysis
        all_rule_results = files_for_language
            .into_par_iter()
            .flat_map(|path| match fs::read_to_string(&path) {
                Ok(file_content) => analyze(
                    language,
                    rules_for_language.clone(),
                    path.strip_prefix(directory_path)
                        .unwrap()
                        .to_str()
                        .expect("path contains non-Unicode characters"),
                    &file_content,
                    &analysis_options,
                ),
                Err(_) => {
                    eprintln!("error when getting content of path {}", &path.display());
                    vec![]
                }
            })
            .collect();
    }

    let value = match output_format {
        OutputFormat::Json => serde_json::to_string(&all_rule_results),
        OutputFormat::Sarif => match generate_sarif_report(&rules, &all_rule_results) {
            Ok(report) => serde_json::to_string(&report),
            Err(_) => {
                panic!("Error when generating the sarif report");
            }
        },
    };

    // write the reports
    let mut file = fs::File::create(output_file).context("cannot create file")?;
    file.write_all(value.expect("cannot get data").as_bytes())
        .context("error when writing results")?;
    Ok(())
}
