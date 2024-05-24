use crate::model::analysis::{
    AnalysisOptions, MatchNode, ERROR_RULE_EXECUTION, ERROR_RULE_TIMEOUT,
};
use crate::model::rule::{RuleInternal, RuleResult};
use crate::model::violation::Violation;
use deno_core::serde_v8;
use deno_core::v8::NewStringType::Internalized;
use deno_core::{v8, JsRuntime};
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::analysis::file_context::common::FileContext;
use serde::{Deserialize, Serialize};

/// The duration an individual execution of `v8` may run before it will be forcefully halted.
const JAVASCRIPT_EXECUTION_TIMEOUT: Duration = Duration::from_millis(5000);

thread_local! {
    static JS_RUNTIME: RefCell<JsRuntime> = {
        let code = deno_core::FastString::from_static(include_str!("./js/stella.js"));
        let mut runtime = JsRuntime::new(Default::default());
        runtime.execute_script("<stella>", code).expect("stella.js should not throw error");
        RefCell::new(runtime)
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
    #[error("error executing JavaScript: {reason}")]
    Execution { reason: String },
    #[error("execution timed out at {:.2}s", .0.as_secs_f32())]
    ExecutionTimeout(Duration),
    #[error("unable to interpret JavaScript: `{reason}`")]
    Interpreter { reason: String },
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
    let execution_start = Instant::now();

    let res = JS_RUNTIME.with_borrow_mut(|runtime| {
        execute_rule_internal(runtime, rule, &match_nodes, &filename, file_context)
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
                ExecutionError::ExecutionTimeout(elapsed) => {
                    if analysis_options.use_debug {
                        eprintln!("rule:file {} TIMED OUT ({} ms)", r_f, elapsed.as_millis());
                    }
                    (ERROR_RULE_TIMEOUT, None)
                }
                ExecutionError::Execution { reason } => {
                    if analysis_options.use_debug {
                        eprintln!("rule:file {} execution error, message: {}", r_f, reason);
                    }
                    (ERROR_RULE_EXECUTION, Some(reason))
                }
                ExecutionError::UnexpectedReturnValue { reason } => {
                    (ERROR_RULE_EXECUTION, Some(reason))
                }
                ExecutionError::Interpreter { reason } => (ERROR_RULE_EXECUTION, Some(reason)),
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
    // NOTE: We merge the existing node context with the file context and resolve key collisions
    // by using the file context's value.
    let js_code = format!(
        r#"
_cleanExecute(() => {{
// Note: variables prefixed with "GLOBAL_" are defined by the static analysis kernel directly via the v8 API.

// The rule's JavaScript code
//////////////////////////////
{}
//////////////////////////////

for (const n of GLOBAL_nodes) {{
    if (Object.keys(GLOBAL_fileContext).length > 0) {{
        n.context = {{...n.context, ...GLOBAL_fileContext}};
    }}
    visit(n, GLOBAL_filename, n.context.code);
}}

return {{
    violations: stellaAllErrors,
    console: console.lines,
}};
}});
"#,
        rule.code
    );

    let iso_handle = runtime.v8_isolate().thread_safe_handle();

    let handle_scope = &mut runtime.handle_scope();
    let ctx = handle_scope.get_current_context();
    let scope = &mut v8::ContextScope::new(handle_scope, ctx);
    let global = ctx.global(scope);

    // The v8 API uses `Option` for fallible calls, with `None` indicating a v8 execution error.
    // We need to use a `TryCatch` scope to actually be able to inspect the error type/contents.
    let tc_scope = &mut v8::TryCatch::new(scope);

    // Serialize each Rust value into a v8 value and send it directly to the v8 isolate (i.e. Rust -> C++).
    // Then have v8 expose these values as global variables within the rule's JavaScript execution context.
    //
    // This is functionally equivalent to assigning a value to JavaScript's `globalThis`.
    // See: https://262.ecma-international.org/13.0/#sec-global-object

    let key_nodes =
        v8::String::new_from_utf8(tc_scope, "GLOBAL_nodes".as_bytes(), Internalized).unwrap();
    let v8_nodes =
        serde_v8::to_v8(tc_scope, match_nodes).expect("MatchNode should be serializable");
    global.set(tc_scope, key_nodes.into(), v8_nodes);

    let key_file_context =
        v8::String::new_from_utf8(tc_scope, "GLOBAL_fileContext".as_bytes(), Internalized).unwrap();
    let v8_file_context =
        serde_v8::to_v8(tc_scope, file_context).expect("FileContext should be serializable");
    global.set(tc_scope, key_file_context.into(), v8_file_context);

    let key_filename =
        v8::String::new_from_utf8(tc_scope, "GLOBAL_filename".as_bytes(), Internalized).unwrap();
    let v8_filename =
        serde_v8::to_v8(tc_scope, filename).expect("filename should be valid v8 string");
    global.set(tc_scope, key_filename.into(), v8_filename);

    let code = v8::String::new(tc_scope, &js_code)
        .expect("dynamically generated JavaScript code should be valid v8 string");

    let compiled_script = v8::Script::compile(tc_scope, code, None).ok_or_else(|| {
        let exception = tc_scope
            .exception()
            .expect("return value should only be `None` if an error was caught");
        let reason = exception.to_rust_string_lossy(tc_scope);
        tc_scope.reset();
        ExecutionError::Interpreter { reason }
    })?;

    let done_flag = Arc::new(AtomicBool::new(false));
    let done_flag_clone = Arc::clone(&done_flag);
    let iso_handle_clone = iso_handle.clone();
    // Spawn a watchdog thread to call into `v8` and terminate the runtime's execution if it exceeds our timeout.
    let timed_out = std::thread::spawn(move || {
        let start = Instant::now();
        let timeout = JAVASCRIPT_EXECUTION_TIMEOUT;
        let mut timeout_remaining = timeout;
        loop {
            std::thread::park_timeout(timeout_remaining);
            let elapsed = start.elapsed();
            if elapsed > timeout {
                iso_handle_clone.terminate_execution();
                break true;
            } else if done_flag_clone.load(Ordering::Relaxed) {
                // The main thread that was executing the JavaScript has toggled this atomic flag, indicating that it's done.
                break false;
            }
            // This was a spurious wakeup. Adjust the timeout for the next call to `park_timeout`.
            timeout_remaining = timeout - elapsed;
        }
    });

    let execution_start = Instant::now();
    let execution_result = compiled_script.run(tc_scope);
    done_flag.store(true, Ordering::Relaxed);
    // This can't deadlock because even if a race causes the atomic bool to be set after the `unpark`,
    // the watchdog thread's call to `park_timeout` will return immediately.
    timed_out.thread().unpark();

    let timed_out = timed_out.join().expect("thread should not panic");
    if timed_out {
        iso_handle.cancel_terminate_execution();
        return Err(ExecutionError::ExecutionTimeout(execution_start.elapsed()));
    }

    let execution_result = execution_result.ok_or_else(|| {
        let exception = tc_scope
            .exception()
            .expect("return value should only be `None` if an error was caught");
        let reason = exception.to_rust_string_lossy(tc_scope);
        tc_scope.reset();
        ExecutionError::Execution { reason }
    })?;

    let StellaExecution {
        mut violations,
        console: output,
    } = serde_v8::from_v8(tc_scope, execution_result).map_err(|err| {
        let reason = err.to_string();
        ExecutionError::UnexpectedReturnValue { reason }
    })?;

    // Drop the objects we created. Because we are re-using the context, it won't happen automatically.
    global.delete(tc_scope, key_nodes.into());
    global.delete(tc_scope, key_file_context.into());
    global.delete(tc_scope, key_filename.into());

    // Override the violation's category and severity with that from the rule.
    for v in violations.iter_mut() {
        v.category = rule.category;
        v.severity = rule.severity;
    }
    Ok(CompletedExecution { violations, output })
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
                ignore_generated_files: false,
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
                ignore_generated_files: false,
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
                ignore_generated_files: false,
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
                ignore_generated_files: false,
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
                ignore_generated_files: false,
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
                ignore_generated_files: false,
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
                ignore_generated_files: false,
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
                ignore_generated_files: false,
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
                ignore_generated_files: false,
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
                ignore_generated_files: false,
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
            "SyntaxError: Unexpected token '}'",
            rule_execution.execution_error.unwrap()
        );
        assert_eq!(1, rule_execution.errors.len());
        assert_eq!(
            crate::model::analysis::ERROR_RULE_EXECUTION,
            rule_execution.errors.get(0).unwrap()
        )
    }
}
