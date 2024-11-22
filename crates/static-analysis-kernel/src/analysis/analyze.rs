use crate::analysis::ddsa_lib::common::DDSAJsRuntimeError;
use crate::analysis::ddsa_lib::js::flow::java::{ClassGraph, FileGraph};
use crate::analysis::ddsa_lib::runtime::ExecutionResult;
use crate::analysis::ddsa_lib::JsRuntime;
use crate::analysis::generated_content::{is_generated_file, is_minified_file};
use crate::analysis::tree_sitter::{get_tree, get_tree_sitter_language, TSQuery};
use crate::model::analysis::{
    FileIgnoreBehavior, LinesToIgnore, ERROR_RULE_EXECUTION, ERROR_RULE_TIMEOUT,
};
use crate::model::common::Language;
use crate::model::rule::{RuleCategory, RuleInternal, RuleResult, RuleSeverity};
use crate::rule_config::RuleConfig;
use common::analysis_options::AnalysisOptions;
use std::borrow::Borrow;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The duration an individual execution of a rule may run before it will be forcefully halted.
/// This includes the time it takes for the tree-sitter query to collect its matches, as well as
/// the time it takes for the JavaScript rule to execute.
const RULE_EXECUTION_TIMEOUT: Duration = Duration::from_millis(2000);

/// Split the code and extract all the logic that reports to lines to ignore.
/// If a no-dd-sa statement occurs on the first line, it applies to the whole file.
/// Otherwise, it only applies to the line below.
fn get_lines_to_ignore(code: &str, language: &Language) -> LinesToIgnore {
    let mut lines_to_ignore_for_all_rules = vec![];
    let mut lines_to_ignore_per_rules: HashMap<u32, Vec<String>> = HashMap::new();

    let mut line_number = 1u32;
    let disabling_patterns = match language {
        Language::Python
        | Language::Starlark
        | Language::Dockerfile
        | Language::Ruby
        | Language::Terraform
        | Language::Yaml
        | Language::Bash
        | Language::R => {
            vec!["#no-dd-sa", "#datadog-disable"]
        }
        Language::JavaScript | Language::TypeScript | Language::Kotlin | Language::Apex => {
            vec![
                "//no-dd-sa",
                "/*no-dd-sa",
                "//datadog-disable",
                "/*datadog-disable",
            ]
        }
        Language::Go | Language::Rust | Language::Csharp | Language::Java | Language::Swift => {
            vec!["//no-dd-sa", "//datadog-disable"]
        }
        Language::Json => {
            vec!["impossiblestringtoreach"]
        }
        Language::PHP => {
            vec![
                "//no-dd-sa",
                "/*no-dd-sa",
                "//datadog-disable",
                "/*datadog-disable",
                "#no-dd-sa",
                "#datadog-disable",
            ]
        }
        Language::Markdown => {
            vec!["<!--no-dd-sa", "<!--datadog-disable"]
        }
        Language::SQL => {
            vec![
                "--no-dd-sa",
                "--datadog-disable",
                "/*no-dd-sa",
                "/*datadog-disable",
            ]
        }
    };
    let mut ignore_file_all_rules: bool = false;
    let mut rules_to_ignore: Vec<String> = vec![];
    for line in code.lines() {
        let line_without_whitespaces: String =
            line.chars().filter(|c| !c.is_whitespace()).collect();
        for p in &disabling_patterns {
            if line_without_whitespaces.contains(p) {
                // get the rulesets/rules being referenced on the line
                let parts: Vec<String> = line
                    .to_string()
                    .replace("//", "")
                    .replace("/*", "")
                    .replace("*/", "")
                    .replace('#', "")
                    .replace("no-dd-sa", "")
                    .replace("datadog-disable", "")
                    .replace(':', "")
                    .replace(',', " ")
                    .split_whitespace()
                    .filter(|e| e.contains('/'))
                    .map(|e| e.to_string())
                    .collect();

                // no ruleset/rules specified, we just ignore everything
                if parts.is_empty() {
                    if line_number == 1 {
                        ignore_file_all_rules = true;
                    } else {
                        lines_to_ignore_for_all_rules.push(line_number + 1);
                    }
                } else if line_number == 1 {
                    rules_to_ignore.extend(parts.clone());
                } else {
                    lines_to_ignore_per_rules.insert(line_number + 1, parts.clone());
                }
            }
        }
        line_number += 1;
    }

    let ignore_file = if ignore_file_all_rules {
        FileIgnoreBehavior::AllRules
    } else {
        FileIgnoreBehavior::SomeRules(rules_to_ignore)
    };

    LinesToIgnore {
        lines_to_ignore: lines_to_ignore_for_all_rules,
        lines_to_ignore_per_rule: lines_to_ignore_per_rules,
        ignore_file,
    }
}

pub fn analyze_with<I>(
    runtime: &mut JsRuntime,
    language: &Language,
    rules: I,
    filename: &Arc<str>,
    code: &Arc<str>,
    rule_config: &RuleConfig,
    analysis_option: &AnalysisOptions,
) -> Vec<RuleResult>
where
    I: IntoIterator,
    I::Item: Borrow<RuleInternal>,
{
    // check if we should ignore the file before doing any more expensive work.
    if analysis_option.ignore_generated_files
        && (is_generated_file(code, language) || is_minified_file(code, language))
    {
        if analysis_option.use_debug {
            eprintln!("Skipping generated file {}", filename);
        }
        return vec![];
    }

    let lines_to_ignore = get_lines_to_ignore(code, language);

    let now = Instant::now();
    let Some(tree) = get_tree(code, language) else {
        if analysis_option.use_debug {
            eprintln!("error when parsing source file {filename}");
        }
        return vec![];
    };
    let tree = Arc::new(tree);
    let cst_parsing_time = now.elapsed();

    let timeout = if let Some(timeout) = analysis_option.timeout {
        Some(Duration::from_millis(timeout))
    } else {
        Some(RULE_EXECUTION_TIMEOUT)
    };

    rules
        .into_iter()
        .filter(|rule| rule_config.rule_is_enabled(&rule.borrow().name))
        .map(|rule| {
            let rule = rule.borrow();
            if analysis_option.use_debug {
                eprintln!("Apply rule {} file {}", rule.name, filename);
            }

            let res = runtime.execute_rule(
                code,
                &tree,
                filename,
                rule,
                &rule_config.get_arguments(&rule.name),
                timeout,
            );

            // NOTE: This is a translation layer to map Result<T, E> to a `RuleResult` struct.
            // Eventually, `analyze` should be refactored to also use a `Result`, and then this will no longer be required.
            let (violations, errors, execution_error, console_output, timing) = match res {
                Ok(execution) => {
                    let ExecutionResult {
                        mut violations,
                        console_lines,
                        timing,
                    } = execution;
                    let console_output = (!console_lines.is_empty() && analysis_option.log_output)
                        .then_some(console_lines.join("\n"));
                    violations.retain(|v| {
                        let base_ignored =
                            lines_to_ignore.should_filter_rule(rule.name.as_str(), v.start.line);
                        // Additionally, ignore the entire flow if any of the individual regions should be ignored.
                        let flow_ignored = v
                            .taint_flow
                            .as_ref()
                            .map(|flow| {
                                flow.iter().any(|region| {
                                    lines_to_ignore
                                        .should_filter_rule(rule.name.as_str(), region.start.line)
                                })
                            })
                            .unwrap_or(false);
                        !(base_ignored || flow_ignored)
                    });
                    violations.iter_mut().for_each(|violation| {
                        if let Some(severity) = rule_config.get_severity(&rule.name) {
                            violation.severity = severity;
                        }
                        if let Some(category) = rule_config.get_category(&rule.name) {
                            violation.category = category;
                        }
                    });
                    (violations, vec![], None, console_output, timing)
                }
                Err(err) => {
                    let r_f = format!("{}:{}", rule.name, filename);
                    let (err_kind, execution_error) = match err {
                        DDSAJsRuntimeError::JavaScriptTimeout { timeout }
                        | DDSAJsRuntimeError::TreeSitterTimeout { timeout } => {
                            if analysis_option.use_debug {
                                eprintln!(
                                    "rule:file {} TIMED OUT ({} ms)",
                                    r_f,
                                    timeout.as_millis()
                                );
                            }
                            (ERROR_RULE_TIMEOUT, None)
                        }
                        other_err => {
                            let reason = other_err.to_string();
                            if analysis_option.use_debug {
                                eprintln!("rule:file {} execution error, message: {}", r_f, reason);
                            }
                            (ERROR_RULE_EXECUTION, Some(reason))
                        }
                    };
                    let errors = vec![err_kind.to_string()];
                    (vec![], errors, execution_error, None, Default::default())
                }
            };
            RuleResult {
                rule_name: rule.name.clone(),
                filename: filename.to_string(),
                violations,
                errors,
                execution_error,
                output: console_output,
                execution_time_ms: timing.execution.as_millis(),
                parsing_time_ms: cst_parsing_time.as_millis(),
                query_node_time_ms: timing.ts_query.as_millis(),
            }
        })
        .collect()
}

/// Returns a [DOT Language] graph that models taint flow within the file.
/// If the file contains an unsupported language, `None` is returned.
///
/// This is an expensive, unoptimized function.
///
/// [DOT Language]: https://graphviz.org/doc/info/lang.html
pub fn generate_flow_graph_dot(
    runtime: &mut JsRuntime,
    language: Language,
    file_name: &Arc<str>,
    file_contents: &Arc<str>,
    rule_config: &RuleConfig,
    analysis_option: &AnalysisOptions,
) -> Option<String> {
    // language=javascript
    let rule_code = r#"
function visit(captures) {
    const classNode = captures.get("class");
    if (classNode?.cstType !== "class_declaration") {
        return;
    }
    const classChildren = ddsa.getChildren(classNode);
    const className = classChildren.find((n) => n.fieldName === "name");

    const classBody = classChildren.find((n) => n.fieldName === "body");
    const bodyChildren = ddsa.getChildren(classBody);
    const graphs = [];
    for (const bodyChild of bodyChildren) {
        if (bodyChild.cstType === "method_declaration") {
            const graph = __ddsaPrivate__.generateJavaFlowGraph(bodyChild);

            // Create a method signature:
            const methodChildren = ddsa.getChildren(bodyChild);
            const type = (methodChildren.find((n) => n.fieldName === "type"))?.text ?? "";
            const name = (methodChildren.find((n) => n.fieldName === "name"))?.text ?? "";
            const params = (methodChildren.find((n) => n.fieldName === "parameters"))?.text ?? "";
            const methodSig = `${type} ${name}${params}`
            graphs.push(__ddsaPrivate__.graphToDOT(graph, methodSig));
        }
    }
    if (graphs.length === 0) {
        return;
    }
    // HACK: Pass structured string data back by repurposing fields of a "Violation":
    // Violation.description -> class name
    // Violation.fixes[i].description -> Serialized DOT graph for individual method
    const violation = Violation.new(className.text, classNode);
    for (const dotGraph of graphs) {
        violation.addFix(Fix.new(dotGraph, []));
    }
    addError(violation);
}
"#;
    let class_tsq = "\
(program (class_declaration) @class)
";
    match language {
        Language::Java => {
            let tree_sitter_query =
                TSQuery::try_new(&get_tree_sitter_language(&language), class_tsq).ok()?;
            let rule = RuleInternal {
                name: "<java-debug>/dataflow-dot".to_string(),
                short_description: None,
                description: None,
                category: RuleCategory::Unknown,
                severity: RuleSeverity::None,
                language,
                code: rule_code.to_string(),
                tree_sitter_query,
            };

            let results = analyze_with(
                runtime,
                &language,
                [rule],
                file_name,
                file_contents,
                rule_config,
                analysis_option,
            );
            let result = results.first().expect("there should be exactly one result");

            if result.violations.is_empty() {
                return None;
            }
            let mut file_graph = FileGraph::new(file_name.as_ref());
            for v in &result.violations {
                let class_name = &v.message;
                let mut class_graph = ClassGraph::new(class_name);
                for fix in &v.fixes {
                    // We pass already-serialized graphs for each method as a "fix description".
                    // Thus, we need to reparse this into a `dot_structures::Graph`.
                    if let Ok(graph) = graphviz_rust::parse(&fix.description) {
                        // (The JavaScript implementation already provides the method signature)
                        class_graph.add_method(graph, None);
                    };
                }
                file_graph.add_class(class_graph);
            }
            Some(file_graph.to_dot())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::analysis::ddsa_lib::test_utils::cfg_test_v8;
    use crate::analysis::tree_sitter::get_query;
    use crate::config_file::parse_config_file;
    use crate::model::common::Language;
    use crate::model::rule::{RuleCategory, RuleSeverity};
    use crate::rule_config::RuleConfigProvider;

    const QUERY_CODE: &str = r#"
(function_definition
    name: (identifier) @name
  parameters: (parameters) @params
)
        "#;

    const PYTHON_CODE: &str = r#"
def foo(arg1):
    pass
        "#;

    /// An ergonomic test-wrapper to avoid needing to manually create a v8 platform.
    fn analyze(
        language: &Language,
        rules: &[RuleInternal],
        filename: &Arc<str>,
        code: &Arc<str>,
        rule_config: &RuleConfig,
        analysis_option: &AnalysisOptions,
    ) -> Vec<RuleResult> {
        let v8 = cfg_test_v8();
        let mut runtime = v8.new_runtime();
        analyze_with(
            &mut runtime,
            language,
            rules,
            filename,
            code,
            rule_config,
            analysis_option,
        )
    }

    // execution time must be more than 0
    #[test]
    fn test_execution_time() {
        let rule_code = r#"
function visit(node, filename, code) {
    const functionName = node.captures["name"];
    if(functionName) {
        const error = buildError(functionName.start.line, functionName.start.col, functionName.end.line, functionName.end.col,
                                 "invalid name", "CRITICAL", "security");

        const edit = buildEdit(functionName.start.line, functionName.start.col, functionName.end.line, functionName.end.col, "update", "bar");
        const fix = buildFix("use bar", [edit]);
        addError(error.addFix(fix));
    }
}
        "#;

        let rule = RuleInternal {
            name: "myrule".to_string(),
            short_description: Some("short desc".to_string()),
            description: Some("description".to_string()),
            category: RuleCategory::CodeStyle,
            severity: RuleSeverity::Notice,
            language: Language::Python,
            code: rule_code.to_string(),
            tree_sitter_query: get_query(QUERY_CODE, &Language::Python).unwrap(),
        };

        let analysis_options = AnalysisOptions::default();
        let results = analyze(
            &Language::Python,
            &vec![rule],
            &Arc::from("myfile.py"),
            &Arc::from(PYTHON_CODE),
            &RuleConfig::default(),
            &analysis_options,
        );
        assert_eq!(1, results.len());
        let result = results.get(0).unwrap();
        assert_eq!(result.violations.len(), 1);
    }

    // execute two rules and check that both rules are executed and their respective
    // results reported.
    #[test]
    fn test_two_rules_executed() {
        let rule_code1 = r#"
function visit(node, filename, code) {
    const functionName = node.captures["name"];
    if(functionName) {
        const error = buildError(functionName.start.line, functionName.start.col, functionName.end.line, functionName.end.col,
                                 "invalid name", "CRITICAL", "security");

        const edit = buildEdit(functionName.start.line, functionName.start.col, functionName.end.line, functionName.end.col, "update", "bar");
        const fix = buildFix("use bar", [edit]);
        addError(error.addFix(fix));
    }
}
        "#;
        let rule_code2 = r#"
function visit(node, filename, code) {
    const functionName = node.captures["name"];
    if(functionName) {
        const error = buildError(functionName.start.line, functionName.start.col, functionName.end.line, functionName.end.col,
                                 "invalid name", "CRITICAL", "security");

        const edit = buildEdit(functionName.start.line, functionName.start.col, functionName.end.line, functionName.end.col, "update", "baz");
        const fix = buildFix("use baz", [edit]);
        addError(error.addFix(fix));
    }
}
        "#;

        let rule1 = RuleInternal {
            name: "myrule".to_string(),
            short_description: Some("short desc".to_string()),
            description: Some("description".to_string()),
            category: RuleCategory::CodeStyle,
            severity: RuleSeverity::Notice,
            language: Language::Python,
            code: rule_code1.to_string(),
            tree_sitter_query: get_query(QUERY_CODE, &Language::Python).unwrap(),
        };
        let rule2 = RuleInternal {
            name: "myrule2".to_string(),
            short_description: Some("short desc".to_string()),
            description: Some("description".to_string()),
            category: RuleCategory::CodeStyle,
            severity: RuleSeverity::Notice,
            language: Language::Python,
            code: rule_code2.to_string(),
            tree_sitter_query: get_query(QUERY_CODE, &Language::Python).unwrap(),
        };

        let analysis_options = AnalysisOptions::default();
        let results = analyze(
            &Language::Python,
            &vec![rule1, rule2],
            &Arc::from("myfile.py"),
            &Arc::from(PYTHON_CODE),
            &RuleConfig::default(),
            &analysis_options,
        );
        assert_eq!(2, results.len());
        let result1 = results.get(0).unwrap();
        let result2 = results.get(1).unwrap();
        assert_eq!(result1.violations.len(), 1);
        assert_eq!(result2.violations.len(), 1);
        assert_eq!(
            result1
                .violations
                .get(0)
                .unwrap()
                .fixes
                .get(0)
                .unwrap()
                .edits
                .get(0)
                .unwrap()
                .content
                .clone()
                .unwrap(),
            "bar".to_string()
        );
        assert_eq!(
            result2
                .violations
                .get(0)
                .unwrap()
                .fixes
                .get(0)
                .unwrap()
                .edits
                .get(0)
                .unwrap()
                .content
                .clone()
                .unwrap(),
            "baz".to_string()
        );
    }

    // execute two rules and check that both rules are executed and their respective
    // results reported.
    #[test]
    fn test_capture_unnamed_nodes() {
        let rule_code1 = r#"
function visit(node, filename, code) {

    const el = node.captures["less_than"];
    if(el) {
        const error = buildError(el.start.line, el.start.col, el.end.line, el.end.col,
                                 "do not use less than", "CRITICAL", "security");
        addError(error);
    }
}
        "#;

        let tree_sitter_query = r#"
(
    (for_statement
        condition: (_
            (binary_expression
                left: (identifier)
                operator: [
                    "<" @less_than
                    "<=" @less_than
                    ">" @more_than
                    ">=" @more_than
                ]
            )
        )
    )
)
        "#;

        let js_code = r#"
for(var i = 0; i <= 10; i--){}
        "#;

        let rule1 = RuleInternal {
            name: "myrule".to_string(),
            short_description: Some("short desc".to_string()),
            description: Some("description".to_string()),
            category: RuleCategory::CodeStyle,
            severity: RuleSeverity::Notice,
            language: Language::JavaScript,
            code: rule_code1.to_string(),
            tree_sitter_query: get_query(tree_sitter_query, &Language::JavaScript).unwrap(),
        };

        let analysis_options = AnalysisOptions::default();
        let results = analyze(
            &Language::JavaScript,
            &vec![rule1],
            &Arc::from("myfile.js"),
            &Arc::from(js_code),
            &RuleConfig::default(),
            &analysis_options,
        );
        assert_eq!(1, results.len());
        let result1 = results.get(0).unwrap();
        assert_eq!(result1.violations.len(), 1);
        assert_eq!(
            result1.violations.get(0).unwrap().message,
            "do not use less than".to_string()
        );
    }

    // do not execute the visit function when there is no match
    #[test]
    fn test_no_unnecessary_execute() {
        let rule_code1 = r#"
function visit(node, filename, code) {

    console.log("bla");
}
        "#;

        let tree_sitter_query = r#"

    (for_statement) @for_statement
    (#eq? @for_statement "bla")

        "#;

        let python_code = r#"
def foo():
  print("bar")
        "#;

        let rule1 = RuleInternal {
            name: "myrule".to_string(),
            short_description: Some("short desc".to_string()),
            description: Some("description".to_string()),
            category: RuleCategory::CodeStyle,
            severity: RuleSeverity::Notice,
            language: Language::Python,
            code: rule_code1.to_string(),
            tree_sitter_query: get_query(tree_sitter_query, &Language::Python).unwrap(),
        };

        let analysis_options = AnalysisOptions::default();
        let results = analyze(
            &Language::Python,
            &vec![rule1],
            &Arc::from("myfile.py"),
            &Arc::from(python_code),
            &RuleConfig::default(),
            &analysis_options,
        );
        assert_eq!(1, results.len());
        let result1 = results.get(0).unwrap();
        assert!(result1.output.as_ref().is_none());
    }

    // test showing violation ignore
    #[test]
    fn test_violation_ignore_single_region() {
        let rule_code = r#"
function visit(node, filename, code) {
    const functionName = node.captures["name"];
    if(functionName) {
        const error = buildError(functionName.start.line, functionName.start.col, functionName.end.line, functionName.end.col,
                                 "invalid name", "CRITICAL", "security");

        const edit = buildEdit(functionName.start.line, functionName.start.col, functionName.end.line, functionName.end.col, "update", "bar");
        const fix = buildFix("use bar", [edit]);
        addError(error.addFix(fix));
    }
}
        "#;

        let c = r#"
# no-dd-sa
def foo(arg1):
    pass
        "#;
        let rule = RuleInternal {
            name: "myrule".to_string(),
            short_description: Some("short desc".to_string()),
            description: Some("description".to_string()),
            category: RuleCategory::CodeStyle,
            severity: RuleSeverity::Notice,
            language: Language::Python,
            code: rule_code.to_string(),
            tree_sitter_query: get_query(QUERY_CODE, &Language::Python).unwrap(),
        };

        let analysis_options = AnalysisOptions::default();
        let results = analyze(
            &Language::Python,
            &vec![rule],
            &Arc::from("myfile.py"),
            &Arc::from(c),
            &RuleConfig::default(),
            &analysis_options,
        );
        assert_eq!(1, results.len());
        let result = results.get(0).unwrap();
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_violation_ignore_taint_flow() {
        // language=java
        let text = "\
class Test {
    // An ignore on a taint flow region (not the base region of the violation):
    // no-dd-sa
    void test(String input) {
        String a = input;
        var b = a;
        execute(b);
    }
}
";
        let ts_query = "\
(argument_list (identifier) @arg)
";
        // language=javascript
        let rule_code = r#"
function visit(captures) {
    const arg = captures.get("arg");
    const sourceFlows = ddsa.getTaintSources(arg);
    const v = Violation.new("flow violation", sourceFlows[0]);
    addError(v);
}
"#;

        let rule = RuleInternal {
            name: "java-security/flow-rule".to_string(),
            short_description: None,
            description: None,
            category: RuleCategory::Security,
            severity: RuleSeverity::Error,
            language: Language::Java,
            code: rule_code.to_string(),
            tree_sitter_query: get_query(ts_query, &Language::Java).unwrap(),
        };

        let analysis_options = AnalysisOptions::default();
        let results = analyze(
            &Language::Python,
            &vec![rule],
            &Arc::from("file.java"),
            &Arc::from(text),
            &RuleConfig::default(),
            &analysis_options,
        );
        assert!(results[0].violations.is_empty());
    }

    fn assert_lines_to_ignore(code: String, language: Language, rule: &'static str) {
        let lines_to_ignore = get_lines_to_ignore(code.as_str(), &language);
        assert_eq!(1, lines_to_ignore.lines_to_ignore_per_rule.len());
        assert_eq!(
            rule,
            lines_to_ignore
                .lines_to_ignore_per_rule
                .get(&3)
                .unwrap()
                .get(0)
                .unwrap()
        );
    }

    #[test]
    fn test_get_lines_to_ignore_with_tabs_and_no_space_from_comment_symbol() {
        // no-dd-sa on line 2 so we ignore line 3 for rule
        let rule = "ruleset/rule1";
        // java
        let code = format!("\n\t//no-dd-sa:{rule}");
        assert_lines_to_ignore(code, Language::Java, rule);
        // js
        let code = format!("\n\t//no-dd-sa:{rule}");
        assert_lines_to_ignore(code, Language::JavaScript, rule);
        // python
        let code = format!("\n\t#no-dd-sa:{rule}");
        assert_lines_to_ignore(code, Language::Python, rule);
    }

    #[test]
    fn test_get_lines_to_ignore_python() {
        // no-dd-sa ruleset1/rule1 on line 3 so we ignore line 4 for ruleset1/rule1
        // no-dd-sa on line 7 so we ignore all rules on line 8
        let code = "\
foo

# no-dd-sa ruleset1/rule1

bar

# no-dd-sa
";

        let lines_to_ignore = get_lines_to_ignore(code, &Language::Python);

        // test lines to ignore for all rules
        assert_eq!(1, lines_to_ignore.lines_to_ignore.len());
        assert!(!lines_to_ignore.lines_to_ignore.contains(&1));
        assert!(lines_to_ignore.lines_to_ignore.contains(&8));

        // test lines to ignore for some rules
        assert_eq!(1, lines_to_ignore.lines_to_ignore_per_rule.len());
        assert!(lines_to_ignore.lines_to_ignore_per_rule.contains_key(&4));
        assert_eq!(
            1,
            lines_to_ignore
                .lines_to_ignore_per_rule
                .get(&4)
                .unwrap()
                .len()
        );
        assert_eq!(
            "ruleset1/rule1",
            lines_to_ignore
                .lines_to_ignore_per_rule
                .get(&4)
                .unwrap()
                .get(0)
                .unwrap()
        );
    }

    #[test]
    fn test_get_lines_to_ignore_python_ignore_all_file() {
        let code = "\
#no-dd-sa
def foo():
  pass";

        let lines_to_ignore = get_lines_to_ignore(code, &Language::Python);
        assert!(lines_to_ignore.lines_to_ignore.is_empty());
        assert!(lines_to_ignore.lines_to_ignore_per_rule.is_empty());
        assert!(matches!(
            lines_to_ignore.ignore_file,
            FileIgnoreBehavior::AllRules
        ));
    }

    #[test]
    fn test_get_lines_to_ignore_python_ignore_all_file_specific_rules() {
        let code1 = "\
#no-dd-sa foo/bar
def foo():
  pass";

        let lines_to_ignore1 = get_lines_to_ignore(code1, &Language::Python);
        assert!(lines_to_ignore1.lines_to_ignore_per_rule.is_empty());
        assert_eq!(
            lines_to_ignore1.ignore_file,
            FileIgnoreBehavior::SomeRules(vec!["foo/bar".to_string()])
        );
        assert!(lines_to_ignore1.lines_to_ignore.is_empty());

        let code2 = "\
#no-dd-sa foo/bar ruleset/rule
def foo():
  pass";

        let lines_to_ignore2 = get_lines_to_ignore(code2, &Language::Python);

        assert!(lines_to_ignore2.lines_to_ignore_per_rule.is_empty());

        assert_eq!(
            lines_to_ignore2.ignore_file,
            FileIgnoreBehavior::SomeRules(vec!["foo/bar".to_string(), "ruleset/rule".to_string()])
        );
        assert!(lines_to_ignore2.lines_to_ignore.is_empty());
    }

    #[test]
    fn test_go_file_context() {
        let code = r#"
import (
    "math/rand"
    crand1 "crypto/rand"
    crand2 "crypto/rand"
)

func main () {

}
        "#;

        let query = r#"(function_declaration) @func"#;

        let rule_code = r#"
function visit(node, filename, code) {
    const n = node.captures["func"];
    console.log(node.context.packages);
    if(node.context.packages.includes("math/rand")) {
        const error = buildError(n.start.line, n.start.col, n.end.line, n.end.col, "invalid name", "CRITICAL", "security");
        addError(error);
    }
}
        "#;

        let rule = RuleInternal {
            name: "myrule".to_string(),
            short_description: Some("short desc".to_string()),
            description: Some("description".to_string()),
            category: RuleCategory::CodeStyle,
            severity: RuleSeverity::Notice,
            language: Language::Go,
            code: rule_code.to_string(),
            tree_sitter_query: get_query(query, &Language::Go).unwrap(),
        };

        let analysis_options = AnalysisOptions {
            log_output: true,
            ..Default::default()
        };
        let results = analyze(
            &Language::Go,
            &vec![rule],
            &Arc::from("myfile.go"),
            &Arc::from(code),
            &RuleConfig::default(),
            &analysis_options,
        );

        assert_eq!(1, results.len());
        let result = results.get(0).unwrap();
        let output = result.output.clone().unwrap();
        assert_eq!(result.violations.len(), 1);
        assert!(output.contains("\"math/rand\""));
        assert!(output.contains("\"crypto/rand\""));
    }

    #[test]
    fn test_get_lines_to_ignore_javascript() {
        // no-dd-sa ruleset1/rule1 on line 3 so we ignore line 4 for ruleset1/rule1
        // no-dd-sa on line 7 so we ignore all rules on line 8
        let code = r#"
 /*
 * no-dd-sa */
line4("bar");
/* no-dd-sa */
line6("bar");
// no-dd-sa ruleset/rule1,ruleset/rule2
line8("bar");
// no-dd-sa ruleset/rule1, ruleset/rule3
line10("bar");
/* no-dd-sa ruleset/rule1, ruleset/rule4 */
line12("bar");
/*no-dd-sa ruleset/rule1, ruleset/rule5*/
line14("bar");
// no-dd-sa:ruleset/rule1
line16("bar");
// no-dd-sa
line18("foo")
//no-dd-sa
line20("foo")
        "#;

        let lines_to_ignore = get_lines_to_ignore(code, &Language::JavaScript);

        // test lines to ignore for all rules
        assert_eq!(3, lines_to_ignore.lines_to_ignore.len());
        assert!(!lines_to_ignore.lines_to_ignore.contains(&1));
        assert!(lines_to_ignore.lines_to_ignore.contains(&18));
        assert!(lines_to_ignore.lines_to_ignore.contains(&20));
        assert_eq!(5, lines_to_ignore.lines_to_ignore_per_rule.len());
        assert_eq!(
            "ruleset/rule1",
            lines_to_ignore
                .lines_to_ignore_per_rule
                .get(&8)
                .unwrap()
                .get(0)
                .unwrap()
        );
        assert_eq!(
            "ruleset/rule2",
            lines_to_ignore
                .lines_to_ignore_per_rule
                .get(&8)
                .unwrap()
                .get(1)
                .unwrap()
        );
        assert_eq!(
            "ruleset/rule1",
            lines_to_ignore
                .lines_to_ignore_per_rule
                .get(&10)
                .unwrap()
                .get(0)
                .unwrap()
        );
        assert_eq!(
            "ruleset/rule3",
            lines_to_ignore
                .lines_to_ignore_per_rule
                .get(&10)
                .unwrap()
                .get(1)
                .unwrap()
        );
        assert_eq!(
            "ruleset/rule1",
            lines_to_ignore
                .lines_to_ignore_per_rule
                .get(&12)
                .unwrap()
                .get(0)
                .unwrap()
        );
        assert_eq!(
            "ruleset/rule4",
            lines_to_ignore
                .lines_to_ignore_per_rule
                .get(&12)
                .unwrap()
                .get(1)
                .unwrap()
        );
        assert_eq!(
            "ruleset/rule1",
            lines_to_ignore
                .lines_to_ignore_per_rule
                .get(&14)
                .unwrap()
                .get(0)
                .unwrap()
        );
        assert_eq!(
            "ruleset/rule5",
            lines_to_ignore
                .lines_to_ignore_per_rule
                .get(&14)
                .unwrap()
                .get(1)
                .unwrap()
        );
    }

    #[test]
    fn test_argument_values() {
        let rule_code = r#"
function visit(node, filename, code) {
    const functionName = node.captures["name"];
    const argumentValue = node.context.arguments['my-argument'];
    if (argumentValue !== undefined) {
        const error = buildError(
            functionName.start.line, functionName.start.col,
            functionName.end.line, functionName.end.col,
            `argument = ${argumentValue}`);
        addError(error);
    }
}
        "#;

        let rule1 = RuleInternal {
            name: "rs/rule1".to_string(),
            short_description: Some("short desc".to_string()),
            description: Some("description".to_string()),
            category: RuleCategory::CodeStyle,
            severity: RuleSeverity::Notice,
            language: Language::Python,
            code: rule_code.to_string(),
            tree_sitter_query: get_query(QUERY_CODE, &Language::Python).unwrap(),
        };
        let rule2 = RuleInternal {
            name: "rs/rule2".to_string(),
            short_description: Some("short desc".to_string()),
            description: Some("description".to_string()),
            category: RuleCategory::CodeStyle,
            severity: RuleSeverity::Notice,
            language: Language::Python,
            code: rule_code.to_string(),
            tree_sitter_query: get_query(QUERY_CODE, &Language::Python).unwrap(),
        };

        let analysis_options = AnalysisOptions::default();
        let rule_config_provider = RuleConfigProvider::from_config(
            &parse_config_file(
                r#"
rulesets:
  - rs:
    rules:
      rule1:
        arguments:
          my-argument: 101
          another-arg: 101
        "#,
            )
            .unwrap(),
        );
        let rule_config = rule_config_provider.config_for_file("myfile.py");

        let results = analyze(
            &Language::Python,
            &vec![rule1, rule2],
            &Arc::from("myfile.py"),
            &Arc::from(PYTHON_CODE),
            &rule_config,
            &analysis_options,
        );

        assert_eq!(2, results.len());
        let result1 = results.get(0).unwrap();
        let result2 = results.get(1).unwrap();
        assert_eq!(result1.violations.len(), 1);
        assert!(result1.violations[0].message.contains("argument = 101"));
        assert_eq!(result2.violations.len(), 0);
    }

    #[test]
    fn test_execution_for_starlark() {
        let rule_code = r#"
function visit(query, filename, code) {
    const functionName = query.captures.name;
    if (functionName) {
        const error = buildError(
            functionName.start.line, functionName.start.col,
            functionName.end.line, functionName.end.col,
            `invalid name`
        );
        addError(error);
    }
}"#;

        let rule = RuleInternal {
            name: "rule1".to_string(),
            short_description: Some("short desc".to_string()),
            description: Some("description".to_string()),
            category: RuleCategory::CodeStyle,
            severity: RuleSeverity::Notice,
            language: Language::Starlark,
            code: rule_code.to_string(),
            tree_sitter_query: get_query(QUERY_CODE, &Language::Starlark).unwrap(),
        };

        let analysis_options = AnalysisOptions::default();

        let starlark_code = r#"
def foo():
    pass
"#;

        let results = analyze(
            &Language::Starlark,
            &vec![rule],
            &Arc::from("myfile.star"),
            &Arc::from(starlark_code),
            &RuleConfig::default(),
            &analysis_options,
        );

        assert_eq!(results.len(), 1);
        let result = results.get(0).unwrap();
        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.violations[0].message, "invalid name");
    }

    #[test]
    fn test_severity_override() {
        let rule_code = r#"
function visit(node, filename, code) {
    const functionName = node.captures["name"];
    const error = buildError(
        functionName.start.line, functionName.start.col,
        functionName.end.line, functionName.end.col,
        `error`);
    addError(error);
}
        "#;

        let rule1 = RuleInternal {
            name: "rs/rule1".to_string(),
            short_description: Some("short desc".to_string()),
            description: Some("description".to_string()),
            category: RuleCategory::CodeStyle,
            severity: RuleSeverity::Notice,
            language: Language::Python,
            code: rule_code.to_string(),
            tree_sitter_query: get_query(QUERY_CODE, &Language::Python).unwrap(),
        };
        let rule2 = RuleInternal {
            name: "rs/rule2".to_string(),
            short_description: Some("short desc".to_string()),
            description: Some("description".to_string()),
            category: RuleCategory::CodeStyle,
            severity: RuleSeverity::Notice,
            language: Language::Python,
            code: rule_code.to_string(),
            tree_sitter_query: get_query(QUERY_CODE, &Language::Python).unwrap(),
        };

        let analysis_options = AnalysisOptions {
            log_output: true,
            use_debug: false,
            ignore_generated_files: false,
            timeout: None,
        };
        let rule_config_provider = RuleConfigProvider::from_config(
            &parse_config_file(
                r#"
rulesets:
  - rs:
    rules:
      rule1:
        severity: ERROR
      rule2:
        severity:
          /: WARNING
          uno: NOTICE
          dos/myfile.py: ERROR
        "#,
            )
            .unwrap(),
        );
        let rules = vec![rule1, rule2];

        let results = analyze(
            &Language::Python,
            &rules,
            &Arc::from("myfile.py"),
            &Arc::from(PYTHON_CODE),
            &rule_config_provider.config_for_file("myfile.py"),
            &analysis_options,
        );
        assert_eq!(
            results.get(0).unwrap().violations[0].severity,
            RuleSeverity::Error
        );
        assert_eq!(
            results.get(1).unwrap().violations[0].severity,
            RuleSeverity::Warning
        );

        let results = analyze(
            &Language::Python,
            &rules,
            &Arc::from("uno/myfile.py"),
            &Arc::from(PYTHON_CODE),
            &rule_config_provider.config_for_file("uno/myfile.py"),
            &analysis_options,
        );
        assert_eq!(
            results.get(0).unwrap().violations[0].severity,
            RuleSeverity::Error
        );
        assert_eq!(
            results.get(1).unwrap().violations[0].severity,
            RuleSeverity::Notice
        );

        let results = analyze(
            &Language::Python,
            &rules,
            &Arc::from("dos/myfile.py"),
            &Arc::from(PYTHON_CODE),
            &rule_config_provider.config_for_file("dos/myfile.py"),
            &analysis_options,
        );
        assert_eq!(
            results.get(0).unwrap().violations[0].severity,
            RuleSeverity::Error
        );
        assert_eq!(
            results.get(1).unwrap().violations[0].severity,
            RuleSeverity::Error
        );

        let results = analyze(
            &Language::Python,
            &rules,
            &Arc::from("tres/myfile.py"),
            &Arc::from(PYTHON_CODE),
            &rule_config_provider.config_for_file("tres/myfile.py"),
            &analysis_options,
        );
        assert_eq!(
            results.get(0).unwrap().violations[0].severity,
            RuleSeverity::Error
        );
        assert_eq!(
            results.get(1).unwrap().violations[0].severity,
            RuleSeverity::Warning
        );
    }

    #[test]
    fn java_taint_flow_dot_graph() {
        // language=java
        let file_contents = "\
public class ClassA {
    void echo(String a) {
		someMethod(a);
    }
}

public class ClassB {
    void echo(String a) {
		someMethod(a);
    }
}
";
        let mut runtime = cfg_test_v8().new_runtime();
        let parsed_dot = generate_flow_graph_dot(
            &mut runtime,
            Language::Java,
            &Arc::from("path/to/file.java"),
            &Arc::from(file_contents),
            &RuleConfig::default(),
            &AnalysisOptions::default(),
        );
        // language=dot
        let expected = r#"
strict digraph "path/to/file.java" {
    label="path/to/file.java"
    subgraph "cluster: ClassA" {
        label=ClassA
        subgraph "cluster: void echo(String a)" {
            label="void echo(String a)"
            "a:3:14"[text=a,line=3,col=14,cstkind=identifier,vkind=cst]
            "(a):3:13"[text="(a)",line=3,col=13,cstkind=argument_list,vkind=cst]
            "someMethod(a):3:3"[text="someMethod(a)",line=3,col=3,cstkind=method_invocation,vkind=cst]
            "a:2:22"[text=a,line=2,col=22,cstkind=identifier,vkind=cst]
            "a:3:14" -> "a:2:22" [kind=dependence]
            "(a):3:13" -> "a:3:14" [kind=dependence]
            "someMethod(a):3:3" -> "(a):3:13" [kind=dependence]
        }
    }
    subgraph "cluster: ClassB" {
        label=ClassB
        subgraph "cluster: void echo(String a)" {
            label="void echo(String a)"
            "a:9:14"[text=a,line=9,col=14,cstkind=identifier,vkind=cst]
            "(a):9:13"[text="(a)",line=9,col=13,cstkind=argument_list,vkind=cst]
            "someMethod(a):9:3"[text="someMethod(a)",line=9,col=3,cstkind=method_invocation,vkind=cst]
            "a:8:22"[text=a,line=8,col=22,cstkind=identifier,vkind=cst]
            "a:9:14" -> "a:8:22" [kind=dependence]
            "(a):9:13" -> "a:9:14" [kind=dependence]
            "someMethod(a):9:3" -> "(a):9:13" [kind=dependence]
        }
    }
}
"#;
        // Reparse and compare structs
        let parsed_dot = graphviz_rust::parse(&parsed_dot.unwrap()).unwrap();
        let expected_dot = graphviz_rust::parse(expected).unwrap();
        assert_eq!(parsed_dot, expected_dot);
    }
}
