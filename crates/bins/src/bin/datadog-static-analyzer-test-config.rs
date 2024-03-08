use anyhow::Result;
use getopts::Options;
use itertools::Itertools;
use kernel::config_file::parse_config_file;
use kernel::model::config_file::{
    ArgumentValues, ConfigFile, PathConfig, RuleConfig, RulesetConfig,
};
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::Read;
use std::process::exit;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    print!("{}", opts.usage(&brief));
}

fn print_cfg(file_name: &str, cfg: &ConfigFile) {
    println!("Configuration file {} parsed correctly.", file_name);
    println!("Schema version: {}", cfg.schema_version);
    for (rs_name, rs_cfg) in &cfg.rulesets {
        print_ruleset(rs_name, rs_cfg);
    }
}

fn print_ruleset(name: &str, cfg: &RulesetConfig) {
    println!("Ruleset: {}", name);
    print_paths("  ", &cfg.paths);
    for (rule_name, rule_cfg) in &cfg.rules {
        print_rule(rule_name, rule_cfg);
    }
}

fn print_rule(name: &str, cfg: &RuleConfig) {
    println!("  Rule: {}", name);
    print_paths("    ", &cfg.paths);
    print_arguments("    ", &cfg.arguments);
}

fn print_paths(indent: &str, paths: &PathConfig) {
    if !paths.ignore.is_empty() {
        println!("{}Ignore: {}", indent, paths.ignore.join(" "));
    }
    if let Some(only) = &paths.only {
        if !only.is_empty() {
            println!("{}Only: {}", indent, only.join(" "));
        }
    }
}

fn print_arguments(indent: &str, arguments: &HashMap<String, ArgumentValues>) {
    if arguments.is_empty() {
        return;
    }
    println!("{}Arguments:", indent);
    for arg in arguments.keys().sorted() {
        println!("{}  {}:", indent, arg);
        let by_subtree = &arguments.get(arg).unwrap().by_subtree;
        for prefix in by_subtree.keys().sorted() {
            let path = if prefix.is_empty() { "/" } else { prefix };
            println!(
                "{}    {}: {}",
                indent,
                path,
                by_subtree.get(prefix).unwrap()
            )
        }
    }
}

fn read_config_file(file_name: &str) -> Result<ConfigFile> {
    let mut file = File::open(file_name)?;
    let mut cfg_file = String::new();
    file.read_to_string(&mut cfg_file)?;
    parse_config_file(&cfg_file)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();

    opts.optopt(
        "c",
        "config",
        "configuration file to test",
        "path/to/static-analysis.datadog.yml",
    );
    opts.optopt(
        "e",
        "expected",
        "expected result of parsing the configuration file",
        "valid/invalid",
    );
    opts.optflag(
        "v",
        "verbose",
        "display information about the configuration file",
    );
    opts.optflag(
        "q",
        "quiet",
        "do not show error messages when there are parse failures",
    );
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

    if !matches.opt_present("c") {
        eprintln!("configuration file not specified");
        print_usage(&program, opts);
        exit(1);
    }

    let expected_valid = matches.opt_str("e").map(|e| {
        if e == "valid" || e == "success" || e == "pass" {
            true
        } else if e == "invalid" || e == "failure" || e == "fail" {
            false
        } else {
            eprintln!("invalid value for the expected result: {}", e);
            print_usage(&program, opts);
            exit(1);
        }
    });

    let file_name = matches.opt_str("c").unwrap();
    let result = read_config_file(&file_name);

    if matches.opt_present("v") {
        if let Ok(cfg) = &result {
            print_cfg(&file_name, cfg);
        }
    }

    match (result, expected_valid) {
        (Ok(_), Some(true)) | (Err(_), Some(false)) | (Ok(_), None) => {
            exit(0);
        }
        (Ok(_), Some(false)) => {
            eprintln!("file {} was unexpectedly valid", file_name);
            exit(1);
        }
        (Err(err), Some(true)) => {
            eprintln!("file {} was unexpectedly invalid: {}", file_name, err);
            exit(1);
        }
        (Err(err), None) => {
            eprintln!("error parsing the configuration file: {}", err);
            exit(1);
        }
    }
}
