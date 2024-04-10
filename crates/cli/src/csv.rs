use csv::Writer;
use kernel::model::rule::RuleResult;

pub fn generate_csv_results(rule_results: &Vec<RuleResult>) -> String {
    let mut wtr = Writer::from_writer(vec![]);
    wtr.write_record([
        "filename",
        "rule",
        "category",
        "severity",
        "message",
        "start_line",
        "start_col",
        "end_line",
        "end_col",
    ])
    .expect("csv serialization without issue");

    for r in rule_results {
        for v in &r.violations {
            wtr.write_record(&[
                r.filename.to_string(),
                r.rule_name.to_string(),
                v.category.to_string(),
                v.severity.to_string(),
                v.message.to_string(),
                v.start.line.to_string(),
                v.start.col.to_string(),
                v.end.line.to_string(),
                v.end.col.to_string(),
            ])
            .expect("csv serialization without issue for violation");
        }
    }

    String::from_utf8(wtr.into_inner().expect("generate CSV file")).expect("generate CSV file")
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
            query_node_time_ms: 0,
            parsing_time_ms: 0,
        }]);
        assert_eq!(res_with_result, "filename,rule,category,severity,message,start_line,start_col,end_line,end_col\nfilename,myrule,performance,error,message,10,12,12,10\n");
    }
}
