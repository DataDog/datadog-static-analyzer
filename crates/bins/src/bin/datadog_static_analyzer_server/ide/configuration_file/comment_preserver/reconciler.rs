use std::collections::HashSet;

use super::models::{Comment, Line};
use kernel::analysis::tree_sitter::get_tree;
use kernel::model::common::Language;
use thiserror::Error;
use tree_sitter::Node;

#[derive(Debug, Error)]
#[error("Reconciler error")]
pub struct ReconcileError {
    #[from]
    pub source: anyhow::Error,
}

pub fn prettify_yaml(content: &str) -> Result<String, ReconcileError> {
    let options = pretty_yaml::config::FormatOptions::default();
    pretty_yaml::format_text(content, &options).map_err(|e| ReconcileError {
        source: anyhow::anyhow!("Failed to format the content: {}", e),
    })
}

/// This is a best-effort comment reconciler, which uses a simple diff algorithm to try to locate
/// comments in the new content.
///
/// The algorithm applies for the majority of the cases affecting the static analysis configuration files but has some limitations:
///
/// * Repeated elements may lead to false positives if there are lines added before or between the existing content.
/// * If the original content uses a different syntax than the one emitted by the serializer, we may not be able to determine the location of those comments (e.g. dictionaries and list can be represented in an abbreviated form)
///  
///
/// # Returns
///
/// If successful, it returns a `Result` containing a `String`. The `String` is the reconciled configuration
/// file content.
///
/// # Errors
///
/// This function will return an error of type `ReconcileError` if:
///
/// * There's an issue getting the tree-sitter tree
/// * There's an issue trying to apply the format to the reconciled yaml content
///
pub fn reconcile_comments(
    original_content: &str,
    new_content: &str,
    prettify: bool,
) -> Result<String, ReconcileError> {
    // parse the original content and look for comments
    let tree = get_tree(original_content, &Language::Yaml).ok_or_else(|| {
        anyhow::anyhow!("Failed to parse the original content with the tree-sitter parser")
    })?;

    let root_node = tree.root_node();

    let mut comments = vec![];
    let mut visited = HashSet::new();
    extract_comments_from_node(root_node, original_content, &mut comments, &mut visited);

    let reconciled_content = reconcile(new_content, &comments);

    // make it pretty?
    if prettify {
        prettify_yaml(&reconciled_content)
    } else {
        Ok(reconciled_content)
    }
}

fn get_related_comments<'a>(
    next: Option<Node<'a>>,
    source: &str,
    visited: &mut HashSet<Node<'a>>,
    comment: &mut String,
) -> Option<Node<'a>> {
    if let Some(next) = next {
        if next.kind() == "comment" {
            // get the comment
            let content = &source[next.start_byte()..next.end_byte()];
            *comment = format!("{}\n{}", comment, content);
            visited.insert(next);
            get_related_comments(next.next_sibling(), source, visited, comment)
        } else {
            Some(next)
        }
    } else {
        None
    }
}

fn extract_comments_from_node<'a>(
    node: Node<'a>,
    source: &str,
    comments: &mut Vec<Comment>,
    visited: &mut HashSet<Node<'a>>,
) {
    if node.kind() == "comment" {
        if visited.contains(&node) {
            return;
        }
        visited.insert(node);

        let start_byte = node.start_byte();
        let end_byte = node.end_byte();
        let comment = &source[start_byte..end_byte];
        let row = node.start_position().row;

        let prev_sibling = node.prev_sibling();

        let final_comment = if prev_sibling
            .filter(|p| p.start_position().row == row)
            .is_some()
        {
            Comment::Inline {
                line: Line::new(row, comment.to_string()),
                original_content: get_line_content(source, start_byte).trim().to_string(),
            }
        } else {
            // this can be a multiline comment
            // let's keep adding lines until next_sibling is not comment
            let mut comment = comment.to_string();
            let last_node =
                get_related_comments(node.next_sibling(), source, visited, &mut comment);
            Comment::Block {
                line: Line::new(row, comment),
                above_line: prev_sibling.map(|prev| {
                    let content = get_line_content(source, prev.end_byte());
                    Line::new(row, content.to_string())
                }),
                below_line: last_node.map(|next| {
                    let content = get_line_content(source, next.start_byte());
                    Line::new(next.start_position().row, content.to_string())
                }),
            }
        };

        comments.push(final_comment);
    }

    for child in node.children(&mut node.walk()) {
        extract_comments_from_node(child, source, comments, visited);
    }
}

fn reconcile(modified: &str, comments: &[Comment]) -> String {
    let mut lines: Vec<String> = modified.lines().map(ToString::to_string).collect();

    for comment in comments {
        match comment {
            Comment::Inline {
                line,
                original_content,
            } => manage_inline_comment(&mut lines, line, original_content),

            Comment::Block {
                line,
                above_line,
                below_line,
            } => manage_block_comment(&mut lines, line, above_line, below_line),
        }
    }
    // rejoin the lines again
    lines.join("\n")
}

fn manage_inline_comment(lines: &mut [String], line: &Line, original_content: &str) {
    // for comments added to a node line, we can detect the row and the original content, and then just go to that line,
    // if the content of the line is the same as the original content, we can add the comment to the end of the line.
    // if the content of the line is different, we have to look for the original content in the document (as it may have been moved)
    // if we find it, we add the comment to the end of the line, if we don't find it, we ignore the comment.
    let current_content = &lines.get(line.row);
    if current_content
        .filter(|c| c.starts_with(original_content))
        .is_some()
    {
        // line is ok, just add the comment
        let comment_added = format!("{} {}", lines[line.row], line.content.clone());
        lines[line.row] = comment_added;
    } else {
        // content is different, try to find the original content in another line
        if let Some((row, found_line)) = lines
            .iter()
            .enumerate()
            .find(|(_, l)| l.trim().starts_with(original_content))
        {
            // we found it, add the comment
            let comment_added = format!("{} {}", found_line, line.content.clone());
            lines[row] = comment_added.to_string();
        } else {
            // ignore comment (or add it to the original line?)
        }
    }
}

fn manage_block_comment(
    lines: &mut Vec<String>,
    line: &Line,
    above_line: &Option<Line>,
    below_line: &Option<Line>,
) {
    // block comment
    // we check the line in the original content, if the content is the same and the line above and below are the same, we add the comment.
    match (above_line, below_line) {
        (Some(above_line), Some(below_line)) => {
            // iterate from the start and try to find a couple of lines
            let (trimmed_above, trimmed_below) =
                (above_line.content.trim(), below_line.content.trim());
            let found = lines.iter().enumerate().find(|(i, l)| {
                lines.get(i + 1).map_or(false, |next| {
                    l.trim().starts_with(trimmed_above) && next.trim().starts_with(trimmed_below)
                })
            });
            if let Some(found) = found {
                // add the comment in the line below
                lines.insert(found.0 + 1, line.content.clone());
            } else {
                // if not found, some lines may have been inserted in between.
                // as most usually comments are placed above the line or in the line (not usually below)
                // we will test for the the below line
                search_and_insert_if_found(&below_line.content, lines, &line.content);
            }
        }
        (Some(above_line), None) => {
            // most probably was the last line
            // start searching from the end
            let trimmed = above_line.content.trim();
            let found = lines
                .iter()
                .enumerate()
                .rev()
                .find(|(_, l)| l.trim().starts_with(trimmed));
            if let Some(found) = found {
                // add the comment in the line below
                lines.insert(found.0 + 1, line.content.clone());
            }
        }
        (None, Some(below_line)) => {
            // most probably was the first line
            // start searching from the beginning
            search_and_insert_if_found(&below_line.content, lines, &line.content);
        }
        (None, None) => {
            // we have a block comment with no context, just add it to the line
            // NOTE: potentially do nothing, this case should not happen
            lines.insert(line.row, line.content.clone());
        }
    }
}

fn search_and_insert_if_found(content: &str, lines: &mut Vec<String>, comment: &str) {
    let trimmed = content.trim();
    let found = lines
        .iter()
        .enumerate()
        .find(|(_, l)| l.trim().starts_with(trimmed));

    if let Some(found) = found {
        // add the comment in the line
        lines.insert(found.0, comment.to_owned());
    }
}

fn get_line_content(source: &str, byte_offset: usize) -> &str {
    let start = source[..byte_offset].rfind('\n').map_or(0, |pos| pos + 1);
    let end = source[byte_offset..]
        .find('\n')
        .map_or(source.len(), |pos| byte_offset + pos);
    let content = &source[start..end];
    content
        .find('#')
        .map_or(content, |index| content[..index].trim_end())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works_for_inline_comments() {
        let original_content = r#"
schema-version: v1
rulesets:
  - java-security
  - java-1 # inline comment for java-1
  - ruleset1:
    rules:
      rule2: # this is rule 2 comment
        only:
          - foo/bar
      rule1:
        ignore:
          - "**"
"#;

        let modified = r#"
schema-version: v1
rulesets:
  - java-security
  - java-1
  - java-2
  - ruleset1:
    rules:
      rule2:
        only:
          - foo/bar
      rule3:
        ignore:
          - "**"
"#;

        let expected = r#"
schema-version: v1
rulesets:
  - java-security
  - java-1 # inline comment for java-1
  - java-2
  - ruleset1:
    rules:
      rule2: # this is rule 2 comment
        only:
          - foo/bar
      rule3:
        ignore:
          - "**"
"#;

        let result = reconcile_comments(original_content, modified, true).unwrap();
        assert_eq!(result.trim(), expected.trim());
    }

    #[test]
    fn it_works_for_block_comments() {
        let original_content = r#"
schema-version: v1
rulesets:
  # this is a comment above java-security
  - java-security
  - java-1
  # multi1
  # multi2
  # multi3
  # multi4
  - ruleset1:
    rules:
      rule2:
        only:
          - foo/bar
      rule1:
        ignore:
          - "**"
"#;

        let modified = r#"
schema-version: v1
rulesets:
  - java-0
  - java-security
  - java-1
  - java-2
  - ruleset1:
    rules:
      rule2:
        only:
          - foo/bar
      rule3:
        ignore:
          - "**"
"#;

        let expected = r#"
schema-version: v1
rulesets:
  - java-0
  # this is a comment above java-security
  - java-security
  - java-1
  - java-2
  # multi1
  # multi2
  # multi3
  # multi4
  - ruleset1:
    rules:
      rule2:
        only:
          - foo/bar
      rule3:
        ignore:
          - "**"
"#;

        let result = reconcile_comments(original_content, modified, true).unwrap();
        assert_eq!(result.trim(), expected.trim());
    }

    #[test]
    fn it_works_mixed() {
        let original_content = r#"
schema-version: v1
rulesets:
  # this is a comment above java-security
  - java-security
  - java-1 # inline comment for java-1
  # multi1
  # multi2
  # multi3
  # multi4
  - ruleset1:
    rules:
      rule2: # this is rule 2 comment
        only:
          - foo/bar
      rule1:
        ignore:
          - "**"
"#;

        let modified = r#"
schema-version: v1
rulesets:
  - java-0
  - java-security
  - java-1
  - java-2
  - ruleset1:
    rules:
      rule2:
        only:
          - foo/bar
      rule3:
        ignore:
          - "**"
"#;

        let expected = r#"
schema-version: v1
rulesets:
  - java-0
  # this is a comment above java-security
  - java-security
  - java-1 # inline comment for java-1
  - java-2
  # multi1
  # multi2
  # multi3
  # multi4
  - ruleset1:
    rules:
      rule2: # this is rule 2 comment
        only:
          - foo/bar
      rule3:
        ignore:
          - "**"
"#;

        let result = reconcile_comments(original_content, modified, true).unwrap();
        assert_eq!(result.trim(), expected.trim());
    }
}
