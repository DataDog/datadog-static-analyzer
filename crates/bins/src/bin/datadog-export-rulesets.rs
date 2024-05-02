use cli::datadog_utils::get_ruleset;
use kernel::constants::VERSION;
use kernel::model::ruleset::RuleSet;

use getopts::Options;
use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::process::exit;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.optopt("o", "output", "output file", "rulesets.json");
    opts.optmulti("r", "ruleset", "ruleset to fetch", "python-security");
    opts.optflag("h", "help", "print this help");
    opts.optflag("v", "version", "shows the version");
    opts.optflag("s", "staging", "use staging");
    opts.optflag("t", "include-testing-rules", "include testing rules");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            panic!("error when parsing arguments: {}", f)
        }
    };

    if matches.opt_present("v") {
        println!("{}", VERSION);
        exit(1);
    }

    if matches.opt_present("h") {
        print_usage(&program, opts);
        exit(1);
    }

    if !matches.opt_present("o") {
        eprintln!("--output not defined");
        print_usage(&program, opts);
        exit(1);
    }

    if !matches.opt_present("r") {
        eprintln!("--ruleset not defined");
        print_usage(&program, opts);
        exit(1);
    }

    let use_staging = matches.opt_present("s");
    let include_testing_rules = matches.opt_present("t");
    let rulesets_names = matches.opt_strs("r");
    let file_to_write = matches.opt_str("o").expect("output file");

    // get the rulesets from the API
    let rulesets: Vec<RuleSet> = rulesets_names
        .iter()
        .map(|ruleset_name| {
            get_ruleset(ruleset_name, use_staging, include_testing_rules)
                .expect("error when reading ruleset")
        })
        .collect();

    let file = File::create(&file_to_write).expect("error when opening the output file");
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, &rulesets).expect("error when writing the file");
    writer.flush().expect("error when writing the file");
    println!(
        "rulesets {} saved in file {}",
        rulesets_names.join(","),
        file_to_write
    );
}
