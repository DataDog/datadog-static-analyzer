use std::env;
use std::fs::File;
use std::io::Read;
use std::process::exit;
use getopts::Options;
use anyhow::Result;
use kernel::config_file::parse_config_file;
use kernel::model::config_file::{ConfigFile, PathConfig, RuleConfig, RulesetConfig};

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    print!("{}", opts.usage(&brief));
}

fn print_cfg(file_name: &str, cfg: &ConfigFile) {
    println!("Configuration file {} parsed correctly.", file_name);
    for (rs_name, rs_cfg) in &cfg.rulesets {
        print_ruleset(rs_name, rs_cfg);
    }
}

fn print_ruleset(name: &str, cfg: &RulesetConfig) {
    println!("Ruleset: {}", name);
    print_paths(1, &cfg.paths);
    for (rule_name, rule_cfg) in &cfg.rules {
        print_rule(rule_name, rule_cfg);
    }
}

fn print_rule(name: &str, cfg: &RuleConfig) {
    println!("  Rule: {}", name);
    print_paths(2, &cfg.paths);
}

fn print_paths(indent: usize, paths: &PathConfig) {
    if !paths.ignore.is_empty() {
        println!("{}ignore: {}", "  ".repeat(indent), paths.ignore.join(" "));
    }
    if let Some(only) = &paths.only {
        if !only.is_empty() {
            println!("{}only: {}", "  ".repeat(indent), only.join(" "));
        }
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();

    opts.optopt("c", "config", "configuration file to test", "path/to/static-analysis.datadog.yml");
    opts.optflag("v", "verbose", "display information about the configuration file");
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

    let file_name = matches.opt_str("c").unwrap();
    let mut file = File::open(&file_name)?;
    let mut cfg_file= String::new();
    file.read_to_string(&mut cfg_file)?;
    let cfg = parse_config_file(&cfg_file)?;

    if matches.opt_present("v") {
        print_cfg(&file_name, &cfg);
    }

    Ok(())
}