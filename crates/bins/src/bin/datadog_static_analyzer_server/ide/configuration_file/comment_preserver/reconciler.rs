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

pub fn reconcile_comments(
    original_content: &str,
    new_content: &str,
) -> Result<String, ReconcileError> {
    // parse the original content and look for comments
    let tree = get_tree(original_content, &Language::Yaml).ok_or_else(|| {
        anyhow::anyhow!("Failed to parse the original content with the tree-sitter parser")
    })?;

    let root_node = tree.root_node();

    let mut comments = vec![];
    extract_comments_from_node(root_node, original_content, &mut comments);

    let reconciled_content = reconcile(new_content, &comments);

    // make it pretty
    let options = pretty_yaml::config::FormatOptions::default();
    let formatted = pretty_yaml::format_text(&reconciled_content, &options)
        .map_err(|e| anyhow::anyhow!("Failed to format the reconciled content: {}", e))?;

    Ok(formatted)
}

fn extract_comments_from_node(node: Node<'_>, source: &str, comments: &mut Vec<Comment>) {
    if node.kind() == "comment" {
        let start_byte = node.start_byte();
        let end_byte = node.end_byte();
        let comment = &source[start_byte..end_byte];
        let row = node.start_position().row;

        let prev = node.prev_sibling();
        let final_comment = prev
            .and_then(|p| {
                if p.start_position().row == row {
                    Some(p)
                } else {
                    None
                }
            })
            .map_or_else(
                || Comment::Block {
                    line: Line::new(row, comment.to_string()),
                    above_line: prev.map(|prev| {
                        let content = get_line_content(source, prev.end_byte());
                        Line::new(row, content.to_string())
                    }),
                    below_line: node.next_sibling().map(|next| {
                        let content = get_line_content(source, next.start_byte());
                        Line::new(next.start_position().row, content.to_string())
                    }),
                },
                |previous_node| Comment::Inline {
                    line: Line::new(row, comment.to_string()),
                    original_content: source[previous_node.start_byte()..start_byte - 1]
                        .to_string(),
                },
            );
        comments.push(final_comment);
    }

    for child in node.children(&mut node.walk()) {
        extract_comments_from_node(child, source, comments);
    }
}

fn reconcile(modified: &str, comments: &[Comment]) -> String {
    let mut lines: Vec<String> = modified.lines().map(ToString::to_string).collect();
    let lines_len = lines.len();

    for comment in comments {
        let line = comment.get_line();
        if line.row < lines_len {
            match comment {
                Comment::Inline {
                    line,
                    original_content,
                } => {
                    manage_inline_comment(&mut lines, line, original_content);
                }
                Comment::Block {
                    line,
                    above_line,
                    below_line,
                } => manage_block_comment(&mut lines, line, above_line, below_line),
            }
        }
    }
    // rejoin the lines again
    lines.join("\n")
}

fn manage_inline_comment(lines: &mut [String], line: &Line, original_content: &str) {
    // for comments added to a node line, we can detect the row and the original content, and then just go to that line,
    // if the content of the line is the same as the original content, we can add the comment to the end of the line.
    // if the content of the line is different, we have to look for the original content in the document, as it may have been moved
    // if we find it, we add the comment to the end of the line, if we don't find it, we add the comment to the end of the line of the original content even if the content is different.
    let current_content = &lines[line.row];
    if current_content.starts_with(original_content) {
        // line is ok, just add the comment
        let comment_added = format!("{} {}", lines[line.row], line.content.clone());
        lines[line.row] = comment_added;
    } else {
        // content is different, try to find the original content in another line
        if let Some((row, found_line)) = lines
            .iter()
            .enumerate()
            .find(|(_, l)| l.starts_with(original_content))
        {
            // we found it, add the comment
            let comment_added = format!("{} {}", found_line, line.content.clone());
            lines[row] = comment_added.to_string();
        } else {
            // ignore comment or add it to the original line?
            // TODO: add option for the user to decide what to do?
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
