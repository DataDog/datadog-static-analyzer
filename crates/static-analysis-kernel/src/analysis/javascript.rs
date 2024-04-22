use crate::model::analysis::{
    AnalysisOptions, MatchNode, ERROR_RULE_CODE_TOO_BIG, ERROR_RULE_EXECUTION, ERROR_RULE_TIMEOUT,
};
use crate::model::rule::{RuleInternal, RuleResult};
use crate::model::violation::Violation;
use deno_core::{v8, FastString, JsRuntime, JsRuntimeForSnapshot, RuntimeOptions, Snapshot};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::analysis::file_context::common::FileContext;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

// how long a rule can execute before it's a timeout.
const JAVASCRIPT_EXECUTION_TIMEOUT_MS: u64 = 5000;

lazy_static! {
    static ref STARTUP_DATA: Vec<u8> = {
        let code: FastString = FastString::from_static(include_str!("./js/stella.js"));
        let mut rt = JsRuntimeForSnapshot::new(Default::default(), Default::default());
        rt.execute_script("common_js", code).unwrap();
        rt.snapshot().to_vec()
    };
}

/// A successful execution of a rule's JavaScript code.
#[derive(Debug, Clone)]
pub struct CompletedExecution {
    /// The violations reported by the rule execution.
    pub violations: Vec<Violation>,
    /// A vector of the JSON-serialized console.log output from the rule.
    pub output: Vec<String>,
}

/// An error when attempting to call into the JavaScript runtime.
#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error("JavaScript code is too large: {byte_len} bytes")]
    CodeTooBig { byte_len: usize },
    #[error("error executing JavaScript: {reason}")]
    Execution { reason: String },
    #[error("execution timed out at {:.2}s", .0.as_secs_f32())]
    ExecutionTimeout(Duration),
    #[error("expected value returned from JavaScript execution: `{reason}`")]
    UnexpectedReturnValue { reason: String },
}

// This structure is what is returned by the JavaScript code
#[derive(Deserialize, Debug, Serialize, Clone)]
struct StellaExecution {
    violations: Vec<Violation>, // the list of violations returned by the rule
    console: Vec<String>,       // the log lines from console.log
}

// execute a rule. It is the exposed function to execute a rule and start the underlying
// JS runtime.
pub fn execute_rule(
    rule: &RuleInternal,
    match_nodes: Vec<MatchNode>,
    filename: String,
    analysis_options: AnalysisOptions,
    file_context: &FileContext,
) -> RuleResult {
    let use_debug = analysis_options.use_debug;

    let execution_start = Instant::now();

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

    let res = thread::scope(|scope| {
        scope.spawn(|| {
            let mut runtime = JsRuntime::new(RuntimeOptions {
                startup_snapshot: Some(Snapshot::Static(&STARTUP_DATA)),
                ..Default::default()
            });

            let handle = runtime.v8_isolate().thread_safe_handle();

            assert!(
                tx_runtime.send(handle).is_ok(),
                "we should be able to send the handle to the main thread"
            );

            let (mutex, cvar) = &*condvar_thread;

            // execute the rule and return
            let res =
                execute_rule_internal(&mut runtime, rule, &match_nodes, &filename, file_context);

            // send the result back
            let send_result_result = tx_result.send(res);
            if use_debug && send_result_result.is_err() {
                eprintln!(
                    "rule {}:{} - error when sending results",
                    rule.name, filename
                );
            }

            let _unused = mutex.lock();
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
        let execution_time_ms = execution_start.elapsed().as_millis();

        // drop the thread. Note that it does not terminate the thread, it just put
        // it out of scope.
        match cond_result {
            Ok(v) => {
                if v.1.timed_out() {
                    if use_debug {
                        eprintln!(
                            "[{}] rule:file {}:{} TIMED OUT, execution time: {} ms",
                            end, rule.name, filename, execution_time_ms
                        );
                    }
                    Err(ExecutionError::ExecutionTimeout(Duration::from_millis(
                        execution_time_ms as u64,
                    )))
                } else if let Ok(res) = rx_result.try_recv() {
                    res
                } else {
                    Err(ExecutionError::Execution {
                        reason: "unable to receive runtime result".to_string(),
                    })
                }
            }
            Err(_) => panic!("mutex should not be poisoned"),
        }
    });
    let execution_time_ms = execution_start.elapsed().as_millis();

    // NOTE: This is a translation layer to map Result<T, E> to a `RuleResult` struct.
    // Eventually, `execute_rule` should be refactored to also use a `Result`, and then this will no longer be required.
    let (violations, errors, execution_error, output) = match res {
        Ok(completed) => {
            let output = (!completed.output.is_empty() && analysis_options.log_output)
                .then_some(completed.output.join("\n"));
            (completed.violations, vec![], None, output)
        }
        Err(err) => {
            let r_f = format!("{}:{}", rule.name, filename);
            let (err_kind, execution_error) = match err {
                ExecutionError::ExecutionTimeout(_) => (ERROR_RULE_TIMEOUT, None),
                ExecutionError::Execution { reason } => {
                    if analysis_options.use_debug {
                        eprintln!("rule:file {} execution error, message: {}", r_f, reason);
                    }
                    (ERROR_RULE_EXECUTION, Some(reason))
                }
                ExecutionError::CodeTooBig { .. } => (ERROR_RULE_CODE_TOO_BIG, None),
                ExecutionError::UnexpectedReturnValue { reason } => {
                    (ERROR_RULE_EXECUTION, Some(reason))
                }
            };
            (vec![], vec![err_kind.to_string()], execution_error, None)
        }
    };
    RuleResult {
        rule_name: rule.name.clone(),
        filename,
        violations,
        errors,
        execution_error,
        output,
        execution_time_ms,
        parsing_time_ms: 0,    // filled later in the execute step
        query_node_time_ms: 0, // filled later in the execute step
    }
}

// execute a rule with deno. It creates the JavaScript runtimes and execute
// the JavaScript code. In the JavaScript code, the last value is what is evaluated
// and ultimately being deserialized into a `StellaExecution` struct.
//
// This is the internal code only, the rule used by the code uses
// `execute_rule`.
fn execute_rule_internal(
    runtime: &mut JsRuntime,
    rule: &RuleInternal,
    match_nodes: &[MatchNode],
    filename: &str,
    file_context: &FileContext,
) -> Result<CompletedExecution, ExecutionError> {
    let nodes_json: String = serde_json::to_string(match_nodes).unwrap();

    let file_context_string = serde_json::to_string(file_context).unwrap_or("{}".to_string());

    // format the JavaScript code that will be executed. Note that we are merging the existing
    // node context with the file-context we calculated for each file.
    let js_code = format!(
        r#"
const filename = "{}";
const file_context = {};

{}

{}.forEach(n => {{
    n.context = {{...n.context, ...file_context}};
    visit(n, filename, n.context.code);
}});

const res = {{
    violations: stellaAllErrors,
    console: console.lines,
}}

res
"#,
        filename, file_context_string, rule.code, nodes_json
    );

    // We cannot have strings that are  too long. Otherwise, the underlying
    // JS engine crashes. So for now, we just return an error if the code is too big/large.
    //
    // See https://github.com/denoland/deno/issues/19638 for more details. Once the issue
    // is resolved, we can remove it and errors will be detected in runtime.execute_script()\
    let byte_len = js_code.len();
    if byte_len >= v8::String::max_length() {
        return Err(ExecutionError::CodeTooBig { byte_len });
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

                            Ok(CompletedExecution {
                                violations: updated_violations,
                                output: stella_execution.console,
                            })
                        }
                        Err(err) => Err(ExecutionError::UnexpectedReturnValue {
                            reason: err.to_string(),
                        }),
                    }
                }
                Err(err) => Err(ExecutionError::UnexpectedReturnValue {
                    reason: err.to_string(),
                }),
            }
        }
        Err(e) => {
            let err_str = e.to_string();
            let reason = err_str
                .find("at rule_code")
                .map_or_else(|| err_str.clone(), |pos| err_str[..pos].to_string());
            Err(ExecutionError::Execution { reason })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::file_context::common::get_empty_file_context;
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
            tree_sitter_query: query,
        };

        let nodes = get_query_nodes(
            &tree,
            &rule.tree_sitter_query,
            "myfile.py",
            c,
            &HashMap::new(),
        );

        let rule_execution = execute_rule(
            &rule,
            nodes,
            "foo.py".to_string(),
            AnalysisOptions {
                use_debug: true,
                log_output: true,
            },
            &get_empty_file_context(),
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
            tree_sitter_query: query,
        };

        let nodes = get_query_nodes(
            &tree,
            &rule.tree_sitter_query,
            "myfile.py",
            c,
            &HashMap::new(),
        );

        let rule_execution = execute_rule(
            &rule,
            nodes,
            "foo.py".to_string(),
            AnalysisOptions {
                use_debug: true,
                log_output: true,
            },
            &get_empty_file_context(),
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
        let query = get_query(q, &Language::Python).unwrap();
        let rule = RuleInternal {
            name: "myrule".to_string(),
            short_description: Some("short desc".to_string()),
            description: Some("description".to_string()),
            category: RuleCategory::CodeStyle,
            severity: RuleSeverity::Notice,
            language: Language::Python,
            code: rule_code.to_string(),
            tree_sitter_query: query,
        };
        let nodes = get_query_nodes(&tree, &rule.tree_sitter_query, "plop", c, &HashMap::new());

        let rule_execution = execute_rule(
            &rule,
            nodes,
            "foo.py".to_string(),
            AnalysisOptions {
                use_debug: true,
                log_output: true,
            },
            &get_empty_file_context(),
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
        // Test for a string
        let q = r#"
(function_definition
    name: (identifier) @name
  parameters: (parameters) @params
)
        "#;

        let rule_code_string = r#"
function visit(node, filename, code) {
    foo = "bla";
    console.log(foo);
}
        "#;

        let rule_code_array = r#"
function visit(node, filename, code) {
    foo = [1, 2, 3];
    console.log(foo);
}
        "#;

        let rule_code_object = r#"
function visit(node, filename, code) {
    foo = node.captures["name"];
    console.log(foo);
}
        "#;

        let rule_code_null = r#"
function visit(node, filename, code) {
    foo = null;
    bar = undefined;
    console.log(foo);
    console.log(bar);
}
        "#;

        let rule_code_number = r#"
function visit(node, filename, code) {
    foo = 42;
    console.log(foo);
}
        "#;

        let c = r#"
def foo(arg1):
    pass
        "#;
        let tree = get_tree(c, &Language::Python).unwrap();
        let query = get_query(q, &Language::Python).unwrap();
        let mut rule = RuleInternal {
            name: "myrule".to_string(),
            short_description: Some("short desc".to_string()),
            description: Some("description".to_string()),
            category: RuleCategory::CodeStyle,
            severity: RuleSeverity::Notice,
            language: Language::Python,
            code: rule_code_string.to_string(),
            tree_sitter_query: query,
        };

        let nodes = get_query_nodes(
            &tree,
            &rule.tree_sitter_query,
            "myfile.py",
            c,
            &HashMap::new(),
        );

        let rule_execution = execute_rule(
            &rule,
            nodes.clone(),
            "foo.py".to_string(),
            AnalysisOptions {
                use_debug: true,
                log_output: true,
            },
            &get_empty_file_context(),
        );

        // execute for string
        assert!(rule_execution.execution_error.is_none());
        assert_eq!(rule_execution.output.unwrap(), "bla");

        // execute with array
        rule.code = rule_code_array.to_string();
        let rule_execution = execute_rule(
            &rule,
            nodes.clone(),
            "foo.py".to_string(),
            AnalysisOptions {
                use_debug: true,
                log_output: true,
            },
            &get_empty_file_context(),
        );

        assert!(rule_execution.execution_error.is_none());
        assert_eq!(rule_execution.output.unwrap(), "[1,2,3]");

        // execute with object
        rule.code = rule_code_object.to_string();
        let rule_execution = execute_rule(
            &rule,
            nodes.clone(),
            "foo.py".to_string(),
            AnalysisOptions {
                use_debug: true,
                log_output: true,
            },
            &get_empty_file_context(),
        );

        assert!(rule_execution.execution_error.is_none());
        assert_eq!(rule_execution.output.unwrap(), "{\"astType\":\"identifier\",\"start\":{\"line\":2,\"col\":5},\"end\":{\"line\":2,\"col\":8},\"fieldName\":null,\"children\":[]}");

        // execute with null
        rule.code = rule_code_null.to_string();
        let rule_execution = execute_rule(
            &rule,
            nodes.clone(),
            "foo.py".to_string(),
            AnalysisOptions {
                use_debug: true,
                log_output: true,
            },
            &get_empty_file_context(),
        );

        assert!(rule_execution.execution_error.is_none());
        assert_eq!(rule_execution.output.unwrap(), "null\nundefined");

        // execute with a number
        rule.code = rule_code_number.to_string();
        let rule_execution = execute_rule(
            &rule,
            nodes.clone(),
            "foo.py".to_string(),
            AnalysisOptions {
                use_debug: true,
                log_output: true,
            },
            &get_empty_file_context(),
        );

        assert!(rule_execution.execution_error.is_none());
        assert_eq!(rule_execution.output.unwrap(), "42");
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
            tree_sitter_query: query,
        };

        let nodes = get_query_nodes(
            &tree,
            &rule.tree_sitter_query,
            "myfile.py",
            c,
            &HashMap::new(),
        );

        let rule_execution = execute_rule(
            &rule,
            nodes,
            "foo.py".to_string(),
            AnalysisOptions {
                use_debug: true,
                log_output: true,
            },
            &get_empty_file_context(),
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
            tree_sitter_query: query,
        };

        let nodes = get_query_nodes(
            &tree,
            &rule.tree_sitter_query,
            "myfile.py",
            c,
            &HashMap::new(),
        );

        let rule_execution = execute_rule(
            &rule,
            nodes,
            "foo.py".to_string(),
            AnalysisOptions {
                use_debug: true,
                log_output: true,
            },
            &get_empty_file_context(),
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
