use crate::model::analysis::{MatchNode, MatchNodeContext, TreeSitterNode};
use common::utils::position_utils::LineColumnIndex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use indexmap::IndexMap;
use common::model::position::Position;


use tree_sitter::{CaptureQuantifier, QueryCursorOptions, QueryCursorState, StreamingIterator};
use common::model::language::Language;
use common::tree_sitter::tree_sitter::get_tree_sitter_language;

/// A wrapper around a [`tree_sitter::Query`].
#[derive(Debug)]
pub struct TSQuery {
    query: tree_sitter::Query,
    capture_names: Vec<Arc<str>>,
}

impl TSQuery {
    pub fn try_new(
        language: &tree_sitter::Language,
        source: &str,
    ) -> Result<Self, tree_sitter::QueryError> {
        let query = tree_sitter::Query::new(language, source)?;
        let capture_names = Self::build_cache(&query);
        Ok(Self {
            query,
            capture_names,
        })
    }

    /// Returns a [`TSQueryCursor`] bound to the provided cursor.
    pub fn with_cursor<'a, 'tree: 'a>(
        &'a self,
        cursor: &'a mut tree_sitter::QueryCursor,
    ) -> TSQueryCursor<'a, 'tree> {
        TSQueryCursor {
            query: &self.query,
            capture_names: self.capture_names.as_slice(),
            cursor: MaybeOwnedMut::Borrowed(cursor),
            captures_scratch: IndexMap::new(),
        }
    }

    /// A convenience function to return a [`TSQueryCursor`].
    ///
    /// This is relatively slow, as it allocates a new [`tree_sitter::QueryCursor`] and drops it after
    /// performing the query. Consider using [`TSQuery::with_cursor`] where possible.
    pub fn cursor(&self) -> TSQueryCursor<'_, '_> {
        let cursor = MaybeOwnedMut::Owned(tree_sitter::QueryCursor::new());
        TSQueryCursor {
            query: &self.query,
            capture_names: self.capture_names.as_slice(),
            cursor,
            captures_scratch: IndexMap::new(),
        }
    }

    /// Generates a cache of the capture names as an [`Arc<str>`].
    fn build_cache(query: &tree_sitter::Query) -> Vec<Arc<str>> {
        query
            .capture_names()
            .iter()
            .map(|&name| Arc::from(name))
            .collect::<Vec<_>>()
    }
}

impl From<tree_sitter::Query> for TSQuery {
    fn from(value: tree_sitter::Query) -> Self {
        let capture_names = TSQuery::build_cache(&value);
        Self {
            query: value,
            capture_names,
        }
    }
}

/// A collection of [`TSQueryCapture`]s from a [`tree_sitter::QueryMatch`].
pub type QueryMatch<T> = Vec<TSQueryCapture<T>>;

/// A stateful struct for iterating over a tree-sitter query's matches.
pub struct TSQueryCursor<'a, 'tree>
where
    'tree: 'a,
{
    query: &'a tree_sitter::Query,
    capture_names: &'a [Arc<str>],
    cursor: MaybeOwnedMut<'a, tree_sitter::QueryCursor>,
    // A scratch IndexMap used to group captures with the same name.
    captures_scratch: IndexMap<u32, TSQueryCapture<tree_sitter::Node<'tree>>>,
}

/// A [`Cow`](std::borrow::Cow)-like enum holding either an owned or mutably borrowed [`T`].
//  Note: we internally use this to give the caller control over allocations when using a `TSQuery`.
enum MaybeOwnedMut<'a, T> {
    Borrowed(&'a mut T),
    Owned(T),
}

impl<'a, 'tree> TSQueryCursor<'a, 'tree> {
    /// Returns all of the tree-sitter query matches in the order that they were found.
    ///
    /// ***Note:*** Because multiple patterns can match the same set of nodes, one match may contain captures
    /// that appear before _(i.e. the source text location)_ some of the captures from a previous match.
    pub fn matches(
        &mut self,
        node: tree_sitter::Node<'tree>,
        text: &'tree str,
        timeout: Option<Duration>,
    ) -> Vec<QueryMatch<tree_sitter::Node<'tree>>> {
        let cursor = match &mut self.cursor {
            MaybeOwnedMut::Borrowed(cursor) => cursor,
            MaybeOwnedMut::Owned(cursor) => cursor,
        };
        let deadline = timeout.and_then(|t| Instant::now().checked_add(t));
        let mut on_progress = move |_: &QueryCursorState| match deadline {
            Some(d) => Instant::now() >= d,
            None => false,
        };
        let mut options = QueryCursorOptions::new();
        if deadline.is_some() {
            options = options.progress_callback(&mut on_progress);
        }

        let m = cursor.matches_with_options(self.query, node, text.as_bytes(), options);
        m.map_deref(|q_match| {
            for capture in q_match.captures {
                self.captures_scratch
                    .entry(capture.index)
                    .and_modify(|qc| qc.push(capture.node))
                    .or_insert_with(|| {
                        let name = Arc::clone(&self.capture_names[capture.index as usize]);
                        // --- If the quantifier is either `+` or `*`, start with an array:
                        // (comment)+ @cap              TSCaptureContent::Multi
                        //
                        // Otherwise, use a scalar:
                        // (comment)  @cap              TSCaptureContent::Single
                        let quantifiers = self.query.capture_quantifiers(q_match.pattern_index);
                        let contents = if matches!(
                            quantifiers[capture.index as usize],
                            CaptureQuantifier::OneOrMore | CaptureQuantifier::ZeroOrMore
                        ) {
                            TSCaptureContent::Multi(vec![capture.node])
                        } else {
                            TSCaptureContent::Single(capture.node)
                        };
                        TSQueryCapture::<tree_sitter::Node> { name, contents }
                    });
            }
            self.captures_scratch
                .drain(..)
                .map(|(_, query_capture)| query_capture)
                .collect::<Vec<_>>()
        })
            .collect::<Vec<_>>()
    }
}

/// An intermediate struct that normalizes a result from a [`tree_sitter::QueryMatch`].
/// It contains the `name` of the capture, as well as data for either:
/// * a single node ([`tree_sitter::QueryCapture`])
/// * multiple nodes ([`tree_sitter::QueryCaptures`])
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct TSQueryCapture<T> {
    pub name: Arc<str>,
    pub contents: TSCaptureContent<T>,
}

impl<T> TSQueryCapture<T> {
    /// Adds a [`T`] as a capture.
    pub fn push(&mut self, value: T) {
        if let TSCaptureContent::Multi(caps) = &mut self.contents {
            caps.push(value);
            return;
        }
        // Otherwise, we need to upgrade the `Single` to a `Multi`.
        let single = std::mem::replace(
            &mut self.contents,
            TSCaptureContent::Multi(Vec::with_capacity(2)),
        );
        let TSCaptureContent::Single(prior_value) = single else {
            unreachable!()
        };
        let TSCaptureContent::Multi(vec) = &mut self.contents else {
            unreachable!()
        };
        vec.push(prior_value);
        vec.push(value);
    }

    /// Creates a new `TsQueryCapture` that is a `SingleCapture`.
    pub fn new_single(name: Arc<str>, value: T) -> TSQueryCapture<T> {
        let contents = TSCaptureContent::<T>::Single(value);
        Self { name, contents }
    }

    /// Creates a new `TsQueryCapture` that is a `MultiCapture`.
    pub fn new_multi(name: Arc<str>, value: impl Into<Vec<T>>) -> TSQueryCapture<T> {
        let contents = TSCaptureContent::<T>::Multi(value.into());
        Self { name, contents }
    }
}

/// An enum describing whether a named capture has one or many captured nodes.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum TSCaptureContent<T> {
    Single(T),
    Multi(Vec<T>),
}


// Get all the match nodes based on a query. For each match, we build a `MatchNode`
// object. This object is deserialized and this is what is passed to the visit function.
// This is the first argument of the visit function.
// This `MatchNode` must have the captures and captures_list attributes that contains
// the values of the captures for the match.
//
// Note that we also add the context to the node that consists of the code and variables.
pub fn get_query_nodes(
    tree: &tree_sitter::Tree,
    query: &TSQuery,
    filename: &str,
    code: &str,
    arguments: &HashMap<String, String>,
) -> Vec<MatchNode> {
    let mut match_nodes: Vec<MatchNode> = vec![];

    let idx = LineColumnIndex::new(code);

    for query_match in query.cursor().matches(tree.root_node(), code, None) {
        let mut captures: HashMap<String, TreeSitterNode> = HashMap::new();
        let mut captures_list: HashMap<String, Vec<TreeSitterNode>> = HashMap::new();
        for capture in query_match {
            let list = match capture.contents {
                TSCaptureContent::Single(node) => {
                    map_node(node, &idx).map(|n| vec![n]).unwrap_or_default()
                }
                TSCaptureContent::Multi(nodes) => nodes
                    .into_iter()
                    .filter_map(|n| map_node(n, &idx))
                    .collect::<Vec<_>>(),
            };
            // All captures are inserted into `captures_list`. However, the prior implementation continually
            // called `insert` on the `captures` map, which ended up re-writing the value every time.
            // Thus, to match this behavior, we take the `last` element of the list to insert into `captures`.
            if let Some(last) = list.last() {
                captures.insert(capture.name.to_string(), last.clone());
                captures_list.insert(capture.name.to_string(), list);
            }
        }

        if !captures.is_empty() {
            match_nodes.push(MatchNode {
                captures: captures.clone(),
                captures_list: captures_list.clone(),
                context: MatchNodeContext {
                    code: Some(code.to_string()),
                    filename: filename.to_string(),
                    arguments: arguments.clone(),
                },
            });
        }
    }
    match_nodes
}

// map a node from the tree-sitter representation into our own internal representation
// this is the representation that is passed to the JavaScript layer and how we represent
// or expose the node to the end-user.
pub fn map_node(node: tree_sitter::Node, idx: &LineColumnIndex) -> Option<TreeSitterNode> {
    fn map_node_internal(
        cursor: &mut tree_sitter::TreeCursor,
        only_named_node: bool,
        idx: &LineColumnIndex,
    ) -> Option<TreeSitterNode> {
        // we do not map space, parenthesis and other non-named nodes if there
        // when `only_named_node` is true (which is `true` for children only).
        if only_named_node && !cursor.node().is_named() {
            return None;
        }

        // map all the children as we should
        let mut children: Vec<TreeSitterNode> = vec![];
        if cursor.goto_first_child() {
            loop {
                // For the child, we only want to capture named nodes to avoid polluting the AST.
                let maybe_child = map_node_internal(cursor, true, idx);
                if let Some(child) = maybe_child {
                    children.push(child);
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
            cursor.goto_parent();
        }

        let start_point = cursor.node().range().start_point;
        let end_point = cursor.node().range().end_point;

        // finally, build the return value.
        let ts_node = TreeSitterNode {
            ast_type: cursor.node().kind().to_string(),
            start: Position {
                line: u32::try_from(start_point.row + 1).unwrap(),
                col: idx
                    .byte_col_to_utf16_col(start_point.row, start_point.column)
                    .unwrap_or(start_point.column as u32 + 1),
            },
            end: Position {
                line: u32::try_from(end_point.row + 1).unwrap(),
                col: idx
                    .byte_col_to_utf16_col(end_point.row, end_point.column)
                    .unwrap_or(end_point.column as u32 + 1),
            },
            field_name: cursor.field_name().map(ToString::to_string),
            children,
        };

        Some(ts_node)
    }

    let mut ts_cursor = node.walk();

    // Initially, we capture both un/named nodes to allow capturing unnamed node from
    // the tree-sitter query.
    map_node_internal(&mut ts_cursor, false, idx)
}

// build the query from tree-sitter
pub fn get_query(
    query_code: &str,
    language: &Language,
) -> Result<TSQuery, tree_sitter::QueryError> {
    let tree_sitter_language = get_tree_sitter_language(language);
    TSQuery::try_new(&tree_sitter_language, query_code)
}

#[cfg(test)]
mod tests {
    use common::model::language::Language;
    use crate::analysis::tree_sitter::{get_query};
    use common::tree_sitter::tree_sitter::get_tree;
    use super::*;

    #[test]
    fn test_map_node_simple() {
        let source_code = r#"
arr = ["foo", "bar"];

def func():
   pass;"#;
        let t = get_tree(source_code, &Language::Python);
        assert!(t.is_some());
        let idx = LineColumnIndex::new(source_code);
        let tree_node = map_node(t.unwrap().root_node(), &idx);
        assert!(tree_node.is_some());
        let root = tree_node.unwrap();
        assert_eq!(2, root.children.len());
        assert_eq!(
            "expression_statement",
            root.children.get(0).unwrap().ast_type
        );
        assert_eq!(
            "function_definition",
            root.children.get(1).unwrap().ast_type
        );
        assert!(root.children.get(1).unwrap().field_name.is_none());
        let function_definition = root.children.get(1).unwrap();
        assert_eq!(
            "name",
            function_definition
                .children
                .get(0)
                .unwrap()
                .field_name
                .clone()
                .unwrap()
        );
    }


    // test the number of node we should retrieve when executing a rule
    #[test]
    fn test_get_query_nodes() {
        let q = r#"
(class_definition
  name: (identifier) @classname
  superclasses: (argument_list
    (identifier)+ @superclasses
  )
)
        "#;

        let c = r#"
 class myClass(Parent):
    def __init__(self):
        pass
        "#;

        let tree = get_tree(c, &Language::Python).unwrap();
        let query = get_query(q, &Language::Python).expect("query defined");
        let query_nodes = get_query_nodes(&tree, &query, "myfile.py", c, &HashMap::new());
        assert_eq!(query_nodes.len(), 1);
        let query_node = query_nodes.get(0).unwrap();
        assert_eq!(2, query_node.captures_list.len());
        assert_eq!(1, query_node.captures_list.get("classname").unwrap().len());
        assert_eq!(
            1,
            query_node.captures_list.get("superclasses").unwrap().len()
        );
        assert_eq!(2, query_node.captures.len());
        assert!(query_node.captures.contains_key("superclasses"));
        let superclasses = query_node.captures.get("superclasses").unwrap();
        assert_eq!(2, superclasses.start.line);
        assert_eq!(16, superclasses.start.col);
        assert_eq!(2, superclasses.end.line);
        assert_eq!(22, superclasses.end.col);
        assert_eq!("identifier", superclasses.ast_type);
        assert_eq!(None, superclasses.field_name);
        assert!(query_node.captures.contains_key("classname"));
    }


    #[test]
    fn ts_query_cursor_matches_timeout() {
        let timeout = Duration::from_millis(500);
        let source = "let x = 1234;\n".repeat(2000);

        let tree = get_tree(&source, &Language::JavaScript).unwrap();
        // (Combinatorial explosion query, which should take longer than the `timeout` duration).
        let query = get_query("(((_)*) @one (_)* @two)", &Language::JavaScript).unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let num_captured = query
                .cursor()
                .matches(tree.root_node(), &source, Some(timeout))
                .len();
            tx.send(num_captured).unwrap();
        });

        let num_captured = rx
            .recv_timeout(timeout * 2)
            .expect("query callback should've halted execution");
        assert!(num_captured > 0);
    }
}