use csv::Writer;
use kernel::model::rule::{RuleCategory, RuleResult, RuleSeverity};
use secrets::model::secret_result::SecretResult;

pub fn generate_csv_results(
    rule_results: &Vec<RuleResult>,
    secrets_results: &[SecretResult],
) -> String {
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
        for v in r.violations.iter().filter(|v| !v.is_suppressed) {
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

    for r in secrets_results {
        for v in r.matches.iter().filter(|v| !v.is_suppressed) {
            wtr.write_record(&[
                r.filename.to_string(),
                r.rule_name.to_string(),
                RuleCategory::Security.to_string(),
                RuleSeverity::Error.to_string(),
                r.message.to_string(),
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

    use kernel::model::rule::{RuleCategory, RuleSeverity};
    use kernel::model::violation::Violation;

    // execution time must be more than 0
    #[test]
    fn test_export_csv() {
        let res_no_result = generate_csv_results(&vec![], &vec![]);
        assert_eq!(
            res_no_result,
            "filename,rule,category,severity,message,start_line,start_col,end_line,end_col\n"
        );
        let res_with_result = generate_csv_results(
            &vec![RuleResult {
                rule_name: "myrule".to_string(),
                filename: "filename".to_string(),
                violations: vec![Violation {
                    start: common::model::position::Position { line: 10, col: 12 },
                    end: common::model::position::Position { line: 12, col: 10 },
                    message: "message".to_string(),
                    severity: RuleSeverity::Error,
                    category: RuleCategory::Performance,
                    fixes: vec![],
                    taint_flow: None,
                    is_suppressed: false,
                }],
                errors: vec![],
                execution_error: None,
                output: None,
                execution_time_ms: 10,
                query_node_time_ms: 0,
                parsing_time_ms: 0,
            }],
            &vec![],
        );
        assert_eq!(res_with_result, "filename,rule,category,severity,message,start_line,start_col,end_line,end_col\nfilename,myrule,performance,error,message,10,12,12,10\n");
    }

    /// The CSV output faithfully serializes whatever col value is stored in the violation.
    /// When the kernel produces UTF-16 columns (e.g. col 3 for a node after "🚀"), the CSV row
    /// contains 3, not the raw byte col (5).
    #[test]
    fn test_export_csv_multibyte_col() {
        let res = generate_csv_results(
            &vec![RuleResult {
                rule_name: "myrule".to_string(),
                filename: "file.py".to_string(),
                violations: vec![Violation {
                    // Simulates a violation whose `col` was computed as UTF-16 (e.g. after 🚀).
                    start: common::model::position::Position { line: 1, col: 3 },
                    end: common::model::position::Position { line: 1, col: 16 },
                    message: "multibyte".to_string(),
                    severity: RuleSeverity::Error,
                    category: RuleCategory::Security,
                    fixes: vec![],
                    taint_flow: None,
                    is_suppressed: false,
                }],
                errors: vec![],
                execution_error: None,
                output: None,
                execution_time_ms: 1,
                query_node_time_ms: 0,
                parsing_time_ms: 0,
            }],
            &vec![],
        );
        assert!(
            res.contains(",1,3,1,16\n"),
            "CSV should contain UTF-16 col 3; got: {res}"
        );
    }
}
