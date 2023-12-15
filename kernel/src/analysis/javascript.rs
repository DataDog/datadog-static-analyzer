use crate::model::analysis::{
    AnalysisOptions, MatchNode, ERROR_RULE_CODE_TOO_BIG, ERROR_RULE_EXECUTION, ERROR_RULE_TIMEOUT,
};
use crate::model::rule::{RuleInternal, RuleResult};
use crate::model::violation::Violation;
use deno_core::{v8, FastString, JsRuntime, RuntimeOptions, Snapshot};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

// how long a rule can execute before it's a timeout.
const JAVASCRIPT_EXECUTION_TIMEOUT_MS: u64 = 5000;

// DENO_SNAPSHOT.bin is created at compile time in build.rs
static STARTUP_DATA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/DENO_SNAPSHOT.bin"));

// This structure is what is returned by the JavaScript code
#[derive(Deserialize, Debug, Serialize, Clone)]
struct StellaExecution {
    violations: Vec<Violation>, // the list of violations returned by the rule
    console: Vec<String>,       // the log lines from console.log
}

// execute a rule. It is the exposed function to execute a rule and start the underlying
// JS runtime.
pub fn execute_rule(
    rule: RuleInternal,
    match_nodes: Vec<MatchNode>,
    filename: String,
    analysis_options: AnalysisOptions,
) -> RuleResult {
    let rule_name_copy = rule.name.clone();
    let filename_copy = filename.clone();
    let rule_name_copy_thr = rule.name.clone();
    let filename_copy_thr = filename.clone();
    let use_debug = analysis_options.use_debug;
    let start = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    // These mutexes and condition variables are used to wait on the execution
    // and have a proper timeout.
    let condvar_main = Arc::new((Mutex::new(()), Condvar::new()));
    let condvar_thread = Arc::clone(&condvar_main);

    // to send the handle of the JS runtime to terminate the runtime
    let (tx_runtime, rx_runtime) = mpsc::channel();
    // To send the result once the execution is complete.
    let (tx_result, rx_result) = mpsc::channel();
    let (lock, cvar) = &*condvar_main;

    let started = lock.lock().expect("should lock mutex");

    thread::spawn(move || {
        let mut runtime = JsRuntime::new(RuntimeOptions {
            startup_snapshot: Some(Snapshot::Static(STARTUP_DATA)),
            ..Default::default()
        });

        let handle = runtime.v8_isolate().thread_safe_handle();

        assert!(
            tx_runtime.send(handle).is_ok(),
            "we should be able to send the handle to the main thread"
        );

        let (mutex, cvar) = &*condvar_thread;

        // execute the rule and return
        let res = execute_rule_internal(
            &mut runtime,
            &rule,
            &match_nodes,
            filename,
            &analysis_options,
        );

        // send the result back
        let send_result_result = tx_result.send(Some(res));
        if use_debug && send_result_result.is_err() {
            eprintln!(
                "rule {}:{} - error when sending results",
                rule_name_copy_thr.clone(),
                filename_copy_thr.clone()
            );
        }

        let _ = mutex.lock();
        // notify the main thread we are done with the execution
        cvar.notify_one();
    });

    let handle = rx_runtime.recv();

    // Wait for the rule to execute. If the rule times out, we return a specific RuleResult
    let cond_result = cvar.wait_timeout(
        started,
        Duration::from_millis(JAVASCRIPT_EXECUTION_TIMEOUT_MS),
    );

    // terminate javascript execution so that the thread we started is stopping
    handle
        .expect("should have a javascript handler")
        .terminate_execution();
    let end = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let execution_time_ms = end - start;

    // drop the thread. Note that it does not terminate the thread, it just put
    // it out of scope.
    match cond_result {
        Ok(v) => {
            if v.1.timed_out() {
                if use_debug {
                    eprintln!(
                        "[{}] rule:file {}:{} TIMED OUT, execution time: {} ms",
                        end,
                        rule_name_copy.as_str(),
                        filename_copy.as_str(),
                        execution_time_ms
                    );
                }
                RuleResult {
                    rule_name: rule_name_copy,
                    filename: filename_copy,
                    violations: vec![],
                    errors: vec![ERROR_RULE_TIMEOUT.to_string()],
                    execution_error: None,
                    output: None,
                    execution_time_ms,
                }
            } else if let Some(res) = rx_result.try_recv().unwrap_or(None) {
                RuleResult {
                    rule_name: res.rule_name,
                    filename: res.filename,
                    violations: res.violations,
                    errors: res.errors,
                    execution_error: res.execution_error,
                    execution_time_ms,
                    output: res.output,
                }
            } else {
                RuleResult {
                    rule_name: rule_name_copy,
                    filename: filename_copy,
                    violations: vec![],
                    errors: vec![ERROR_RULE_EXECUTION.to_string()],
                    execution_error: None,
                    output: None,
                    execution_time_ms,
                }
            }
        }
        Err(_) => RuleResult {
            rule_name: rule_name_copy,
            filename: filename_copy,
            violations: vec![],
            errors: vec![ERROR_RULE_EXECUTION.to_string()],
            execution_error: None,
            output: None,
            execution_time_ms,
        },
    }
}

// execute a rule with deno. It creates the JavaScript runtimes and execute
// the JavaScript code. In the JavaScript code, the last value is what is evaluated
// and ultimately being deserialized into a `StellaExecution` struct.
//
// This is the internal code only, the rule used by the code uses
// `execute_rule`.
//
// # Errors
// Errors are reported in the `RuleResult` structure, in the executionError.
pub fn execute_rule_internal(
    runtime: &mut JsRuntime,
    rule: &RuleInternal,
    match_nodes: &[MatchNode],
    filename: String,
    analysis_options: &AnalysisOptions,
) -> RuleResult {
    let nodes_json: String = serde_json::to_string(match_nodes).unwrap();

    // format the JavaScript code that will be executed
    let js_code = format!(
        r#"
const filename = "{}";

{}

{}.forEach(n => visit(n, filename, n.context.code));

const res = {{
    violations: stellaAllErrors,
    console: console.lines,
}}

res
"#,
        filename, rule.code, nodes_json
    );

    // We cannot have strings that are  too long. Otherwise, the underlying
    // JS engine crashes. So for now, we just return an error if the code is too big/large.
    //
    // See https://github.com/denoland/deno/issues/19638 for more details. Once the issue
    // is resolved, we can remove it and errors will be detected in runtime.execute_script()
    if js_code.len() >= v8::String::max_length() {
        return RuleResult {
            rule_name: rule.name.clone(),
            filename,
            violations: vec![],
            errors: vec![ERROR_RULE_CODE_TOO_BIG.to_string()],
            execution_error: Some(ERROR_RULE_CODE_TOO_BIG.to_string()),
            output: None,
            execution_time_ms: 0,
        };
    }

    let code: FastString = js_code.into();

    let execution_result = runtime.execute_script("rule_code", code);

    match execution_result {
        Ok(res) => {
            let scope = &mut runtime.handle_scope();

            let local = v8::Local::new(scope, res);
            // Deserialize a `v8` object into a Rust type using `serde_v8`,
            // in this case deserialize to a JSON `Value`.
            let deserialized_value = serde_v8::from_v8::<serde_json::Value>(scope, local);

            match deserialized_value {
                Ok(value) => {
                    match serde_json::from_value::<StellaExecution>(value) {
                        Ok(stella_execution) => {
                            let console_lines = if stella_execution.console.is_empty()
                                || !analysis_options.log_output
                            {
                                None
                            } else {
                                Some(stella_execution.console.join("\n"))
                            };
                            // update the violation with the category and severity of the rule
                            let updated_violations: Vec<Violation> = stella_execution
                                .violations
                                .into_iter()
                                .map(|v| Violation {
                                    start: v.start,
                                    end: v.end,
                                    message: v.message,
                                    category: rule.category,
                                    severity: rule.severity,
                                    fixes: v.fixes,
                                })
                                .collect();
                            RuleResult {
                                rule_name: rule.name.clone(),
                                filename,
                                violations: updated_violations,
                                errors: vec![],
                                execution_error: None,
                                output: console_lines,
                                execution_time_ms: 0,
                            }
                        }
                        Err(e) => RuleResult {
                            rule_name: rule.name.clone(),
                            filename,
                            violations: vec![],
                            errors: vec![],
                            execution_error: Some(format!("error when getting violations: ${e}")),
                            output: None,
                            execution_time_ms: 0,
                        },
                    }
                }
                Err(err) => RuleResult {
                    rule_name: rule.name.clone(),
                    filename,
                    violations: vec![],
                    errors: vec![ERROR_RULE_EXECUTION.to_string()],
                    execution_error: Some(format!("error: {err}")),
                    output: None,
                    execution_time_ms: 0,
                },
            }
        }
        Err(e) => {
            if analysis_options.use_debug {
                println!(
                    "error when executing the rule {} on file {}, message: {}",
                    rule.name, filename, e
                );
            }

            let err_str = e.to_string();
            let error_message = err_str
                .find("at rule_code")
                .map_or_else(|| err_str.clone(), |pos| err_str[..pos].to_string());

            RuleResult {
                rule_name: rule.name.clone(),
                filename,
                violations: vec![],
                errors: vec![ERROR_RULE_EXECUTION.to_string()],
                execution_error: Some(error_message),
                output: None,
                execution_time_ms: 0,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::tree_sitter::{get_query, get_query_nodes, get_tree};
    use crate::model::common::Language;
    use crate::model::rule::{RuleCategory, RuleSeverity};
    use std::collections::HashMap;

    #[test]
    fn test_execute_rule() {
        let q = r#"
(class_definition
  name: (identifier) @classname
  superclasses: (argument_list
    (identifier)+ @superclasses
  )
)
        "#;

        let rule_code = r#"
        function visit(node, filename, code) {
        }
        "#;

        let c = r#"
 class myClass(Parent):
    def __init__(self):
        pass
        "#;
        let tree = get_tree(c, &Language::Python).unwrap();
        let query = get_query(q, &Language::Python).unwrap();
        let rule = RuleInternal {
            name: "myrule".to_string(),
            short_description: Some("short desc".to_string()),
            description: Some("description".to_string()),
            category: RuleCategory::CodeStyle,
            severity: RuleSeverity::Notice,
            language: Language::Python,
            code: rule_code.to_string(),
            tree_sitter_query: Some(q.to_string()),
            variables: HashMap::new(),
        };

        let nodes = get_query_nodes(&tree, &query, "myfile.py", c, &HashMap::new());

        let rule_execution = execute_rule(
            rule,
            nodes,
            "foo.py".to_string(),
            AnalysisOptions {
                use_debug: true,
                log_output: true,
            },
        );
        assert_eq!("myrule", rule_execution.rule_name);
        assert!(rule_execution.execution_error.is_none());
    }

    #[test]
    fn test_infinite_loop_in_rule() {
        let q = r#"
(function_definition
    name: (identifier) @name
  parameters: (parameters) @params
)
        "#;

        let rule_code = r#"
function visit(node, filename, code) {

    var foo = 10;
    while(true) {
      const a = foo + 12;
      const b = a - 12;
      foo = b;
    }
}
        "#;

        let c = r#"
def foo(arg1):
    pass
        "#;
        let tree = get_tree(c, &Language::Python).unwrap();
        let query = get_query(q, &Language::Python).unwrap();
        let rule = RuleInternal {
            name: "myrule".to_string(),
            short_description: Some("short desc".to_string()),
            description: Some("description".to_string()),
            category: RuleCategory::CodeStyle,
            severity: RuleSeverity::Notice,
            language: Language::Python,
            code: rule_code.to_string(),
            tree_sitter_query: Some(q.to_string()),
            variables: HashMap::new(),
        };

        let nodes = get_query_nodes(&tree, &query, "myfile.py", c, &HashMap::new());

        let rule_execution = execute_rule(
            rule,
            nodes,
            "foo.py".to_string(),
            AnalysisOptions {
                use_debug: true,
                log_output: true,
            },
        );
        assert_eq!("myrule", rule_execution.rule_name);
        assert!(rule_execution.execution_error.is_none());
        assert_eq!(0, rule_execution.violations.len());
        assert_eq!(1, rule_execution.errors.len());
        assert_eq!(
            &ERROR_RULE_TIMEOUT.to_string(),
            rule_execution.errors.get(0).unwrap()
        );
    }

    #[test]
    fn test_execute_with_error_reported() {
        let q = r#"
(function_definition
    name: (identifier) @name
  parameters: (parameters) @params
)
        "#;

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
def foo(arg1):
    pass
        "#;
        let tree = get_tree(c, &Language::Python).unwrap();
        let rule = RuleInternal {
            name: "myrule".to_string(),
            short_description: Some("short desc".to_string()),
            description: Some("description".to_string()),
            category: RuleCategory::CodeStyle,
            severity: RuleSeverity::Notice,
            language: Language::Python,
            code: rule_code.to_string(),
            tree_sitter_query: Some(q.to_string()),
            variables: HashMap::new(),
        };
        let query = get_query(q, &Language::Python).unwrap();
        let nodes = get_query_nodes(&tree, &query, "plop", c, &HashMap::new());

        let rule_execution = execute_rule(
            rule,
            nodes,
            "foo.py".to_string(),
            AnalysisOptions {
                use_debug: true,
                log_output: true,
            },
        );
        assert_eq!("myrule", rule_execution.rule_name);
        assert!(rule_execution.execution_error.is_none());
        assert_eq!(1, rule_execution.violations.len());
        assert_eq!(2, rule_execution.violations.get(0).unwrap().start.line);
        assert_eq!(5, rule_execution.violations.get(0).unwrap().start.col);
        assert_eq!(2, rule_execution.violations.get(0).unwrap().end.line);
        assert_eq!(8, rule_execution.violations.get(0).unwrap().end.col);
        assert_eq!(
            RuleCategory::CodeStyle,
            rule_execution.violations.get(0).unwrap().category
        );
        assert_eq!(
            RuleSeverity::Notice,
            rule_execution.violations.get(0).unwrap().severity
        );
    }

    #[test]
    fn test_execute_with_console() {
        let q = r#"
(function_definition
    name: (identifier) @name
  parameters: (parameters) @params
)
        "#;

        let rule_code = r#"
function visit(node, filename, code) {
    console.log("bla");
}
        "#;

        let c = r#"
def foo(arg1):
    pass
        "#;
        let tree = get_tree(c, &Language::Python).unwrap();
        let query = get_query(q, &Language::Python).unwrap();
        let rule = RuleInternal {
            name: "myrule".to_string(),
            short_description: Some("short desc".to_string()),
            description: Some("description".to_string()),
            category: RuleCategory::CodeStyle,
            severity: RuleSeverity::Notice,
            language: Language::Python,
            code: rule_code.to_string(),
            tree_sitter_query: Some(q.to_string()),
            variables: HashMap::new(),
        };

        let nodes = get_query_nodes(&tree, &query, "myfile.py", c, &HashMap::new());

        let rule_execution = execute_rule(
            rule,
            nodes,
            "foo.py".to_string(),
            AnalysisOptions {
                use_debug: true,
                log_output: true,
            },
        );
        assert_eq!("myrule", rule_execution.rule_name);
        assert!(rule_execution.execution_error.is_none());
        assert_eq!("bla", rule_execution.output.unwrap())
    }

    // change the type of the edit, which should trigger a serialization issue
    #[test]
    fn test_execute_with_serialization_issue() {
        let q = r#"
(function_definition
    name: (identifier) @name
  parameters: (parameters) @params
)
        "#;

        let rule_code = r#"
function visit(node, filename, code) {

    const functionName = node.captures["name"];
    if(functionName) {
        const error = buildError(functionName.start.line, functionName.start.col, functionName.end.line, functionName.end.col,
                                 "invalid name", "CRITICAL", "security");

        const edit = buildEdit(functionName.start.line, functionName.start.col, functionName.end.line, functionName.end.col, "23232", "bar");
        const fix = buildFix("use bar", [edit]);
        addError(error.addFix(fix));
    }
}
        "#;

        let c = r#"
def foo(arg1):
    pass
        "#;
        let tree = get_tree(c, &Language::Python).unwrap();
        let query = get_query(q, &Language::Python).unwrap();
        let rule = RuleInternal {
            name: "myrule".to_string(),
            short_description: Some("short desc".to_string()),
            description: Some("description".to_string()),
            category: RuleCategory::CodeStyle,
            severity: RuleSeverity::Notice,
            language: Language::Python,
            code: rule_code.to_string(),
            tree_sitter_query: Some(q.to_string()),
            variables: HashMap::new(),
        };

        let nodes = get_query_nodes(&tree, &query, "myfile.py", c, &HashMap::new());

        let rule_execution = execute_rule(
            rule,
            nodes,
            "foo.py".to_string(),
            AnalysisOptions {
                use_debug: true,
                log_output: true,
            },
        );
        assert_eq!("myrule", rule_execution.rule_name);
        println!("error: {:?}", rule_execution);
        assert!(rule_execution.execution_error.is_some());
        assert!(rule_execution
            .execution_error
            .unwrap()
            .contains("expected one of `ADD`, `REMOVE`, `UPDATE`"));
    }

    // invalid javascript code
    #[test]
    fn test_invalid_javascript() {
        let q = r#"
(function_definition
    name: (identifier) @name
  parameters: (parameters) @params
)
        "#;

        let rule_code = r#"
function visit(node, filena
}
        "#;

        let c = r#"
def foo(arg1):
    pass
        "#;
        let tree = get_tree(c, &Language::Python).unwrap();
        let query = get_query(q, &Language::Python).unwrap();
        let rule = RuleInternal {
            name: "myrule".to_string(),
            short_description: Some("short desc".to_string()),
            description: Some("description".to_string()),
            category: RuleCategory::CodeStyle,
            severity: RuleSeverity::Notice,
            language: Language::Python,
            code: rule_code.to_string(),
            tree_sitter_query: Some(q.to_string()),
            variables: HashMap::new(),
        };

        let nodes = get_query_nodes(&tree, &query, "myfile.py", c, &HashMap::new());

        let rule_execution = execute_rule(
            rule,
            nodes,
            "foo.py".to_string(),
            AnalysisOptions {
                use_debug: true,
                log_output: true,
            },
        );
        assert_eq!("myrule", rule_execution.rule_name);
        assert!(rule_execution.execution_error.is_some());
        println!(
            "message: {}",
            rule_execution.execution_error.clone().unwrap()
        );
        assert_eq!(
            "Uncaught SyntaxError: Unexpected token '}'\n    ",
            rule_execution.execution_error.unwrap()
        );
        assert_eq!(1, rule_execution.errors.len());
        assert_eq!(
            crate::model::analysis::ERROR_RULE_EXECUTION,
            rule_execution.errors.get(0).unwrap()
        )
    }
}
