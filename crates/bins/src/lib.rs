use crate::AnalysisRulesResult::{SecretsRulesResults, StaticAnalysisRulesResults};
use cli::constants::EXIT_CODE_RULE_CHECKSUM_INVALID;
use cli::file_utils::{filter_files_for_language, get_language_for_file};
use cli::model::cli_configuration::CliConfiguration;
use cli::rule_utils::{check_rules_checksum, convert_rules_to_rules_internal};
use common::analysis_options::AnalysisOptions;
use indicatif::ProgressBar;
use kernel::analysis::analyze::{analyze_with, generate_flow_graph_dot};
use kernel::analysis::ddsa_lib::v8_platform::initialize_v8;
use kernel::analysis::ddsa_lib::JsRuntime;
use kernel::classifiers::{is_test_file, ArtifactClassification};
use kernel::model::analysis::ERROR_RULE_TIMEOUT;
use kernel::model::common::Language;
use kernel::model::rule::{RuleInternal, RuleResult};
use rayon::prelude::*;
use secrets::model::secret_result::SecretResult;
use secrets::scanner::{build_sds_scanner, find_secrets};
use std::cell::Cell;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::Arc;
use std::time::Duration;

/// Read a file and if the file has some invalid UTF-8 characters, it returns a string with invalid
/// characters.
pub fn read_file(path: &Path) -> anyhow::Result<String> {
    let bytes = fs::read(path).map_err(|e| anyhow::anyhow!("cannot read file: {}", e))?;
    match String::from_utf8(bytes) {
        Ok(s) => Ok(s),
        Err(e) => {
            let bytes = e.into_bytes();
            Ok(String::from_utf8_lossy(&bytes).to_string())
        }
    }
}

pub struct CliResults {
    pub static_analysis: Option<AnalysisResult>,
    pub secrets: Option<AnalysisResult>,
}

/// Represent the analysis rules results for either static analysis or secret
pub enum AnalysisRulesResult {
    StaticAnalysisRulesResults(Vec<RuleResult>),
    SecretsRulesResults(Vec<SecretResult>),
}

impl AnalysisRulesResult {
    pub fn get_static_analysis_results(&self) -> &Vec<RuleResult> {
        match self {
            StaticAnalysisRulesResults(results) => results,
            SecretsRulesResults(_) => {
                panic!("wrong call")
            }
        }
    }

    pub fn get_secrets_results(&self) -> &Vec<SecretResult> {
        match self {
            StaticAnalysisRulesResults(_) => {
                panic!("wrong call")
            }
            SecretsRulesResults(results) => results,
        }
    }
}

/// Whatever is returned by static analysis or secrets, including debugging information
pub struct AnalysisResult {
    pub rule_results: AnalysisRulesResult,
    pub metadata: HashMap<String, ArtifactClassification>,
}

pub fn static_analysis(
    config: &CliConfiguration,
    options: &AnalysisOptions,
    files_to_analyze: &[PathBuf],
    languages: &[Language],
) -> anyhow::Result<AnalysisResult> {
    let mut all_rule_results = Vec::<RuleResult>::new();
    let mut all_stats = AnalysisStatistics::new();
    let v8 = initialize_v8(config.get_num_threads() as u32);

    let mut all_path_metadata_static_analysis =
        HashMap::<String, Option<ArtifactClassification>>::new();
    if config.should_verify_checksum {
        if let Err(e) = check_rules_checksum(config.rules.as_slice()) {
            eprintln!("error when checking rules checksum: {e}");
            exit(EXIT_CODE_RULE_CHECKSUM_INVALID)
        }
    }

    let directory_path = Path::new(config.source_directory.as_str());

    // Finally run the analysis
    for language in languages {
        let files_for_language = filter_files_for_language(files_to_analyze, language);

        if files_for_language.is_empty() {
            continue;
        }

        // we only use the progress bar when the debug mode is not active, otherwise, it puts
        // too much information on the screen.
        let progress_bar = if !config.use_debug {
            Some(ProgressBar::new(files_for_language.len() as u64))
        } else {
            None
        };

        let rules_for_language: Vec<RuleInternal> =
            convert_rules_to_rules_internal(config, language)?;

        println!(
            "Analyzing {} {:?} files using {} rules",
            files_for_language.len(),
            language,
            rules_for_language.len()
        );

        if config.use_debug {
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
                    let rule_config = config
                        .rule_config_provider
                        .config_for_file(relative_path.as_ref());
                    let res = if let Ok(file_content) = read_file(&path) {
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
                            options,
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

                        if options.debug_java_dfa && *language == Language::Java {
                            if let Some(graph) = generate_flow_graph_dot(
                                runtime_ref,
                                *language,
                                &relative_path,
                                &file_content,
                                &rule_config,
                                options,
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
            let existing = all_path_metadata_static_analysis.insert(k, v);
            // The `path_metadata` map will only contain file paths for a single `Language`.
            // Because a file only (currently) maps to a single `Language`, it's guaranteed that
            // the key will be unique.
            debug_assert!(existing.is_none());
        }

        if let Some(pb) = &progress_bar {
            pb.finish();
        }
    }

    if config.show_performance_statistics {
        show_performance_statistics(&all_stats);
    }

    let all_path_metadata = all_path_metadata_static_analysis
        .into_iter()
        .filter_map(|(k, v)| v.map(|classification| (k, classification)))
        .collect::<HashMap<_, _>>();

    let analyzer_result = AnalysisResult {
        rule_results: StaticAnalysisRulesResults(all_rule_results),
        metadata: all_path_metadata,
    };
    Ok(analyzer_result)
}

pub fn secret_analysis(
    config: &CliConfiguration,
    options: &AnalysisOptions,
    files_to_analyze: &[PathBuf],
) -> anyhow::Result<AnalysisResult> {
    let secrets_rules = &config.secrets_rules;
    let sds_scanner = build_sds_scanner(secrets_rules, config.use_debug);

    let nb_secrets_files = files_to_analyze.len();
    let directory_path = Path::new(config.source_directory.as_str());
    let progress_bar = if !config.use_debug {
        Some(ProgressBar::new(nb_secrets_files as u64))
    } else {
        None
    };

    let (secrets_results, path_metadata) = files_to_analyze
        .into_par_iter()
        .fold(
            || (Vec::new(), HashMap::new()),
            |(_, mut path_metadata), path| {
                let relative_path = path
                    .strip_prefix(directory_path)
                    .expect("cannot strip prefix from path")
                    .to_str()
                    .expect("path contains non-Unicode characters");
                let res = if let Ok(file_content) = read_file(path) {
                    let file_content = Arc::from(file_content);
                    let secrets = find_secrets(
                        &sds_scanner,
                        secrets_rules,
                        relative_path,
                        &file_content,
                        options,
                    );

                    if !secrets.is_empty() {
                        let cloned_path_str = relative_path.to_string();
                        let language_opt = get_language_for_file(path);

                        if let Some(language) = language_opt {
                            let metadata = if is_test_file(
                                language,
                                file_content.as_ref(),
                                Path::new(&cloned_path_str),
                                None,
                            ) {
                                Some(ArtifactClassification { is_test_file: true })
                            } else {
                                None
                            };
                            path_metadata.insert(cloned_path_str.clone(), metadata);
                        }
                    }

                    secrets
                } else {
                    // this is generally because the file is binary.
                    if config.use_debug {
                        eprintln!("error when getting content of path {}", path.display());
                    }
                    vec![]
                };
                if let Some(pb) = &progress_bar {
                    pb.inc(1);
                }
                (res, path_metadata)
            },
        )
        .reduce(
            || (Vec::new(), HashMap::new()),
            |mut base, other| {
                let (other_results, other_classifications) = other;
                base.0.extend(other_results);
                for (k, v) in other_classifications {
                    base.1.insert(k, v);
                }
                base
            },
        );

    if let Some(pb) = &progress_bar {
        pb.finish();
    }

    let analyzer_result = AnalysisResult {
        rule_results: SecretsRulesResults(secrets_results),
        metadata: path_metadata
            .into_iter()
            .filter_map(|(k, v)| v.map(|classification| (k, classification)))
            .collect::<HashMap<_, _>>(),
    };
    Ok(analyzer_result)
}

pub fn show_performance_statistics(all_stats: &AnalysisStatistics) {
    // The time spent performing a tree-sitter query and running the JavaScript
    let mut analysis_times =
        Vec::<(&str, Duration, Duration, usize)>::with_capacity(all_stats.agg_execution_time.len());
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
    analysis_times.sort_by_key(|&(_, query, execution, _)| std::cmp::Reverse(query + execution));

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

// The `AnalysisStatistics` struct is "tacked" onto this file here.
// We'll eventually refactor this to be implemented with tracing and the subscriber pattern.
// Thus, this should be seen as a temporary implementation.

type RuleName = String;
type FileName = String;

/// The maximum number of file parse times to store in an [`AnalysisStatistic`] `file_parse_time` heap.
pub const STATS_MAX_PARSE_TIMES: usize = 100;

/// A struct containing statistics about an analysis.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct AnalysisStatistics {
    /// The per-rule aggregate amount of time spent on a v8 execution.
    pub agg_execution_time: HashMap<RuleName, Aggregate>,
    /// The per-rule aggregate amount of time spent on performing tree-sitter queries.
    pub agg_query_time: HashMap<RuleName, Aggregate>,
    /// The per-rule list of filenames that timed out.
    pub execution_timeouts: HashMap<RuleName, Vec<FileName>>,
    /// The per-rule list of filenames that caused an execution error.
    pub execution_errors: HashMap<RuleName, Vec<FileName>>,
    /// A max heap of the per-file amount of time spent on tree-sitter tree parsing.
    pub file_parse_time: std::collections::BTreeSet<(Duration, FileName)>,
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
pub struct Aggregate {
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
