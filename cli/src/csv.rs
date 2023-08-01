use kernel::model::rule::RuleResult;

pub fn generate_csv_results(rule_results: &Vec<RuleResult>) -> String {
    let mut result = String::new();
    result.push_str(
        "filename,rule,category,severity,message,start_line,start_col,end_line,end_col\n",
    );
    for r in rule_results {
        for v in &r.violations {
            result.push_str(
                format!(
                    "{},{},{},{},{},{},{},{},{}\n",
                    r.filename,
                    r.rule_name,
                    v.category,
                    v.severity,
                    v.message,
                    v.start.line,
                    v.start.col,
                    v.end.line,
                    v.end.col
                )
                .as_str(),
            );
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    use kernel::model::common::Position;
    use kernel::model::rule::{RuleCategory, RuleSeverity};
    use kernel::model::violation::Violation;

    // execution time must be more than 0
    #[test]
    fn test_export_csv() {
        let res_no_result = generate_csv_results(&vec![]);
        assert_eq!(
            res_no_result,
            "filename,rule,category,severity,message,start_line,start_col,end_line,end_col\n"
        );
        let res_with_result = generate_csv_results(&vec![RuleResult {
            rule_name: "myrule".to_string(),
            filename: "filename".to_string(),
            violations: vec![Violation {
                start: Position { line: 10, col: 12 },
                end: Position { line: 12, col: 10 },
                message: "message".to_string(),
                severity: RuleSeverity::Error,
                category: RuleCategory::Performance,
                fixes: vec![],
            }],
            errors: vec![],
            execution_error: None,
            output: None,
            execution_time_ms: 10,
        }]);
        assert_eq!(res_with_result, "filename,rule,category,severity,message,start_line,start_col,end_line,end_col\nfilename,myrule,performance,error,message,10,12,12,10\n");
    }
}
