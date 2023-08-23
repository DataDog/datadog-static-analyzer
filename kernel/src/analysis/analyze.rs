use crate::analysis::javascript::execute_rule;
use crate::analysis::tree_sitter::{get_query, get_query_nodes, get_tree};
use crate::model::analysis::{AnalysisOptions, ERROR_INVALID_QUERY};
use crate::model::common::Language;
use crate::model::rule::{RuleInternal, RuleResult};
use std::collections::HashMap;

fn get_lines_to_ignore(code: &str, language: &Language) -> Vec<u32> {
    let mut lines_to_ignore = vec![];
    let mut line_number = 1u32;
    let disabling_patterns = match language {
        Language::Python | Language::Dockerfile => {
            vec!["#no-dd-sa"]
        }
        Language::JavaScript | Language::TypeScript => {
            vec!["//no-dd-sa", "/*no-dd-sa*/"]
        }
        Language::Go | Language::Rust | Language::Csharp | Language::Java => {
            vec!["//no-dd-sa", "//no:dd-sa"]
        }
        Language::Json => {
            vec!["impossiblestringtoreach"]
        }
    };

    for line in code.lines() {
        let line_without_whitespaces: String =
            line.chars().filter(|c| !c.is_whitespace()).collect();
        for p in &disabling_patterns {
            if line_without_whitespaces.contains(p) {
                lines_to_ignore.push(line_number + 1);
            }
        }
        line_number += 1;
    }
    lines_to_ignore
}

// main function
// 1. Build the context (tree-sitter tree, etc)
// 2. Run the tree-sitter query and build the object that hold the match
// 3. Execute the rule
// 4. Collect results and errors
pub fn analyze(
    language: &Language,
    rules: Vec<RuleInternal>,
    filename: &str,
    code: &str,
    analysis_option: &AnalysisOptions,
) -> Vec<RuleResult> {
    let lines_to_ignore = get_lines_to_ignore(code, language);

    get_tree(code, language).map_or_else(
        || {
            if analysis_option.use_debug {
                eprintln!("error when parsing source file {filename}");
            }
            vec![]
        },
        |tree| {
            rules
                .into_iter()
                .map(|rule| {
                    let invalid_query_result = RuleResult {
                        rule_name: rule.name.clone(),
                        filename: filename.to_string(),
                        violations: vec![],
                        errors: vec![ERROR_INVALID_QUERY.to_string()],
                        execution_error: None,
                        execution_time_ms: 0,
                        output: None,
                    };

                    if analysis_option.use_debug {
                        eprintln!("Apply rule {} file {}", rule.name, filename);
                    }

                    if let Some(tree_sitter_query) = &rule.tree_sitter_query {
                        let query_try = get_query(tree_sitter_query.as_str(), &rule.language);

                        match query_try {
                            Ok(query) => {
                                let nodes =
                                    get_query_nodes(&tree, &query, filename, code, &HashMap::new());

                                if nodes.is_empty() {
                                    RuleResult {
                                        rule_name: rule.name.clone(),
                                        filename: filename.to_string(),
                                        violations: vec![],
                                        errors: vec![],
                                        execution_error: None,
                                        execution_time_ms: 0,
                                        output: None,
                                    }
                                } else {
                                    let mut rule_result = execute_rule(
                                        rule,
                                        nodes,
                                        filename.to_string(),
                                        analysis_option.clone(),
                                    );

                                    // filter violations that have been ignored
                                    rule_result.violations = rule_result
                                        .violations
                                        .iter()
                                        .cloned()
                                        .filter(|v| !lines_to_ignore.contains(&v.start.line))
                                        .collect();
                                    rule_result
                                }
                            }
                            Err(_) => invalid_query_result,
                        }
                    } else {
                        invalid_query_result
                    }
                })
                .collect()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::common::Language;
    use crate::model::rule::{RuleCategory, RuleSeverity};
    use std::collections::HashMap;

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

    // execution time must be more than 0
    #[test]
    fn test_execution_time() {
        let rule_code = r#"
function visit(node, filename, code) {
    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
    sleep(10);
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
            tree_sitter_query: Some(QUERY_CODE.to_string()),
            variables: HashMap::new(),
        };

        let analysis_options = AnalysisOptions {
            log_output: true,
            use_debug: false,
        };
        let results = analyze(
            &Language::Python,
            vec![rule],
            "myfile.py",
            PYTHON_CODE,
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
    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
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
    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
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
            tree_sitter_query: Some(QUERY_CODE.to_string()),
            variables: HashMap::new(),
        };
        let rule2 = RuleInternal {
            name: "myrule".to_string(),
            short_description: Some("short desc".to_string()),
            description: Some("description".to_string()),
            category: RuleCategory::CodeStyle,
            severity: RuleSeverity::Notice,
            language: Language::Python,
            code: rule_code2.to_string(),
            tree_sitter_query: Some(QUERY_CODE.to_string()),
            variables: HashMap::new(),
        };

        let analysis_options = AnalysisOptions {
            log_output: true,
            use_debug: false,
        };
        let results = analyze(
            &Language::Python,
            vec![rule1, rule2],
            "myfile.py",
            PYTHON_CODE,
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
            tree_sitter_query: Some(tree_sitter_query.to_string()),
            variables: HashMap::new(),
        };

        let analysis_options = AnalysisOptions {
            log_output: true,
            use_debug: false,
        };
        let results = analyze(
            &Language::JavaScript,
            vec![rule1],
            "myfile.js",
            js_code,
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

    // test showing violation ignore
    #[test]
    fn test_violation_ignore() {
        let rule_code = r#"
function visit(node, filename, code) {
    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
    sleep(10);
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
            tree_sitter_query: Some(QUERY_CODE.to_string()),
            variables: HashMap::new(),
        };

        let analysis_options = AnalysisOptions {
            log_output: true,
            use_debug: false,
        };
        let results = analyze(
            &Language::Python,
            vec![rule],
            "myfile.py",
            c,
            &analysis_options,
        );
        assert_eq!(1, results.len());
        let result = results.get(0).unwrap();
        assert!(result.violations.is_empty());
    }

    // test what happens when there is no tree-sitter
    #[test]
    fn test_execution_invalid_query() {
        let rule = RuleInternal {
            name: "myrule".to_string(),
            short_description: Some("short desc".to_string()),
            description: Some("description".to_string()),
            category: RuleCategory::CodeStyle,
            severity: RuleSeverity::Notice,
            language: Language::Python,
            code: "code".to_string(),
            tree_sitter_query: None, // None means there is no query or we fail to parse it
            variables: HashMap::new(),
        };

        let analysis_options = AnalysisOptions {
            log_output: true,
            use_debug: false,
        };
        let results = analyze(
            &Language::Python,
            vec![rule],
            "myfile.py",
            "code",
            &analysis_options,
        );
        assert_eq!(1, results.len());
        let result = results.get(0).unwrap();
        assert_eq!(1, result.errors.len());
        assert_eq!(
            &ERROR_INVALID_QUERY.to_string(),
            result.errors.get(0).unwrap()
        )
    }
}
