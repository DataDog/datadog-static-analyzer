use cli::datadog_utils::get_ruleset;
use kernel::analysis::analyze::analyze;
use kernel::model::analysis::AnalysisOptions;
use kernel::model::rule::Rule;

use anyhow::{Error, Result};
use getopts::Options;
use kernel::arguments::ArgumentProvider;
use kernel::model::rule_test::RuleTest;
use kernel::utils::decode_base64_string;
use std::env;
use std::process::exit;
use std::sync::Arc;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    print!("{}", opts.usage(&brief));
}

fn test_rule(rule: &Rule, test: &RuleTest) -> Result<String> {
    let rule_internal = rule.to_rule_internal().unwrap();
    let code = decode_base64_string(test.code_base64.to_string()).unwrap();
    let code = Arc::from(code);
    let analysis_options = AnalysisOptions {
        log_output: true,
        use_debug: true,
        ignore_generated_files: false,
    };
    let rules = vec![rule_internal];
    let analyze_result = analyze(
        &rule.language,
        &rules,
        &Arc::from(test.filename.clone()),
        &code,
        &ArgumentProvider::new(),
        &analysis_options,
    );

    if analyze_result.is_empty() {
        Err(Error::msg("no violation result"))
    } else {
        let first_results = analyze_result.first().unwrap();

        if first_results.violations.len() != test.annotation_count as usize {
            let error =
                format!(
                "error evaluating test {}, expected {} annotations, got {}, execution error: {}, output: {}, rule errors: {}",
                test.filename,
                test.annotation_count,
                first_results.violations.len(),
                first_results.execution_error.clone().unwrap_or("none".to_string()),
                first_results.output.clone().unwrap_or("none".to_string()),
                first_results.errors.join(",")
            );
            Err(Error::msg(error))
        } else {
            Ok("test pass".to_string())
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();

    opts.optmulti("r", "ruleset", "rules to test", "python-security");
    opts.optflag("h", "help", "print this help");
    opts.optflag("s", "staging", "use staging");
    opts.optflag("t", "include-testing-rules", "include testing rules");

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

    let use_staging = matches.opt_present("s");
    let rulesets = matches.opt_strs("r");
    let mut num_failures = 0;
    for ruleset in rulesets {
        match get_ruleset(ruleset.as_str(), use_staging) {
            Ok(r) => {
                println!("Testing ruleset {}", r.name);
                for rule in r.rules.clone() {
                    println!("   rule {} ... ", rule.name);
                    let c = rule.clone();
                    for t in rule.tests {
                        match test_rule(&c, &t) {
                            Ok(_) => {
                                println!("      test {} passed", t.filename);
                            }
                            Err(e) => {
                                println!("      test {} FAILED ({})", t.filename, e);
                                num_failures += 1;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("error when trying to fetch the ruleset: {}", e);
            }
        }
    }

    exit(num_failures)
}
