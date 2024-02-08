use kernel::model::rule::RuleResult;
use prettytable::{format, Table};

pub fn print_violations_table(rule_results: &Vec<RuleResult>) {
    let mut table = Table::new();
    let format = format::FormatBuilder::new()
        .separator(
            format::LinePosition::Title,
            format::LineSeparator::new('-', '-', '-', '-'),
        )
        .padding(1, 1)
        .build();
    table.set_format(format);
    table.set_titles(row![
        "rule", "filename", "location", "category", "severity", "message"
    ]);
    for rule_result in rule_results {
        if !rule_result.violations.is_empty() {
            for violation in &rule_result.violations {
                let position = format!(
                    "{}:{}-{}:{}",
                    violation.start.line,
                    violation.start.col,
                    violation.end.line,
                    violation.end.col
                );
                table.add_row(row![
                    rule_result.rule_name,
                    rule_result.filename,
                    position,
                    violation.category.to_string(),
                    violation.severity.to_string(),
                    violation.message
                ]);
            }
        }
    }
    table.printstd();
}
