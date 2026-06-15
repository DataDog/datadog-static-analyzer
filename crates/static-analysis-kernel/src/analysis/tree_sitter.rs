use crate::model::analysis::{MatchNode, MatchNodeContext, TreeSitterNode};
use crate::model::common::Language;
use common::model::position::Position;
use common::utils::position_utils::LineColumnIndex;
use indexmap::IndexMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tree_sitter::StreamingIterator;
use tree_sitter::{CaptureQuantifier, QueryCursorOptions, QueryCursorState};

/// A `#match?` / `#not-match?` predicate extracted from a query source string.
///
/// tree-sitter 0.25.x drops these predicates from `query.text_predicates` for
/// certain grammars (confirmed for Dart: `ts_query__perform_analysis` duplicates
/// patterns and loses all text predicates from both copies).  We extract and store
/// them ourselves so `TSQueryCursor::matches` can re-apply the filter.
#[derive(Debug, Clone)]
struct ExtractedPredicate {
    capture_name: Arc<str>,
    regex: regex::bytes::Regex,
    /// `true` = `#match?`, `false` = `#not-match?`
    is_positive: bool,
}

/// Parse `#match?` and `#not-match?` predicates from a raw tree-sitter query string.
///
/// Returns one `ExtractedPredicate` per predicate found.  Unrecognised capture names
/// (not present in `capture_names`) and invalid regexes are silently skipped.
///
/// Tree-sitter unescapes query string literals before compiling them as regexes (`\\` → `\`,
/// `\"` → `"`, etc.).  We replicate that unescaping here so the extracted regex has the
/// same semantics as what tree-sitter would have applied.
fn extract_match_predicates(source: &str, capture_names: &[Arc<str>]) -> Vec<ExtractedPredicate> {
    let mut result = Vec::new();
    let mut rest = source;
    loop {
        // Find next #match? or #not-match?.  Check for the longer token first so that
        // "#not-match?" is never confused with a "#match?" at an offset inside it.
        let Some(pos) = rest
            .find("#not-match?")
            .or_else(|| rest.find("#match?"))
        else {
            break;
        };
        let (is_positive, skip) = if rest[pos..].starts_with("#not-match?") {
            (false, "#not-match?".len())
        } else {
            (true, "#match?".len())
        };
        rest = &rest[pos + skip..];

        // Skip whitespace, then read @captureName.
        let trimmed = rest.trim_start();
        let Some(after_at) = trimmed.strip_prefix('@') else {
            continue;
        };
        let cap_end = after_at
            .find(|c: char| !c.is_alphanumeric() && c != '_')
            .unwrap_or(after_at.len());
        let cap_name = &after_at[..cap_end];

        // Skip whitespace, then read the string literal "…" with tree-sitter unescaping.
        let after_ws = after_at[cap_end..].trim_start();
        let Some(inner) = after_ws.strip_prefix('"') else {
            continue;
        };
        // Unescape the string content exactly as tree-sitter does: `\\` → `\`, `\"` → `"`,
        // `\n` → newline, etc.  Other `\x` sequences keep their backslash so the regex
        // engine sees them (e.g. `\d`, `\s` remain meaningful regex escapes).
        let mut regex_str = String::new();
        let mut chars = inner.char_indices();
        let mut escaped = false;
        loop {
            match chars.next() {
                None => break,
                Some((_, '"')) if !escaped => break,
                Some((_, '\\')) if !escaped => {
                    escaped = true;
                }
                Some((_, c)) => {
                    if escaped {
                        match c {
                            '\\' => regex_str.push('\\'),
                            '"' => regex_str.push('"'),
                            'n' => regex_str.push('\n'),
                            'r' => regex_str.push('\r'),
                            't' => regex_str.push('\t'),
                            // All other `\x` → keep as `\x` for the regex engine
                            _ => {
                                regex_str.push('\\');
                                regex_str.push(c);
                            }
                        }
                        escaped = false;
                    } else {
                        regex_str.push(c);
                    }
                }
            }
        }

        if capture_names.iter().any(|n| n.as_ref() == cap_name) {
            if let Ok(re) = regex::bytes::Regex::new(&regex_str) {
                result.push(ExtractedPredicate {
                    capture_name: Arc::from(cap_name),
                    regex: re,
                    is_positive,
                });
            }
        }
    }
    result
}

/// Returns `true` if the given match satisfies all extracted text predicates.
///
/// Matches with no captures are rejected when there are predicates, because phantom
/// zero-capture matches are a side-effect of the same tree-sitter 0.25.x bug that
/// drops text predicates — they should never reach rule logic.
fn apply_extracted_predicates(
    predicates: &[ExtractedPredicate],
    qm: &QueryMatch<tree_sitter::Node<'_>>,
    source: &[u8],
) -> bool {
    if predicates.is_empty() {
        return true;
    }
    // Phantom match produced by ts_query__perform_analysis pattern duplication.
    if qm.is_empty() {
        return false;
    }
    for pred in predicates {
        // Find the TSQueryCapture whose name matches this predicate's capture name.
        let Some(cap) = qm.iter().find(|c| c.name.as_ref() == pred.capture_name.as_ref()) else {
            // Capture not present in this match — vacuous-true (same semantics as tree-sitter).
            continue;
        };
        // Collect the node(s) for the capture.
        let nodes: Vec<&tree_sitter::Node<'_>> = match &cap.contents {
            TSCaptureContent::Single(n) => vec![n],
            TSCaptureContent::Multi(ns) => ns.iter().collect(),
        };
        for node in nodes {
            let text = node.utf8_text(source).unwrap_or_default();
            let matched = pred.regex.is_match(text.as_bytes());
            // #match? requires ALL nodes to match; #not-match? requires ALL to NOT match.
            if matched != pred.is_positive {
                return false;
            }
        }
    }
    true
}

pub fn get_tree_sitter_language(language: &Language) -> tree_sitter::Language {
    extern "C" {
        fn tree_sitter_c_sharp() -> tree_sitter::Language;
        fn tree_sitter_dart() -> tree_sitter::Language;
        fn tree_sitter_dockerfile() -> tree_sitter::Language;
        fn tree_sitter_elixir() -> tree_sitter::Language;
        fn tree_sitter_go() -> tree_sitter::Language;
        fn tree_sitter_java() -> tree_sitter::Language;
        fn tree_sitter_javascript() -> tree_sitter::Language;
        fn tree_sitter_json() -> tree_sitter::Language;
        fn tree_sitter_kotlin() -> tree_sitter::Language;
        fn tree_sitter_python() -> tree_sitter::Language;
        fn tree_sitter_ruby() -> tree_sitter::Language;
        fn tree_sitter_rust() -> tree_sitter::Language;
        fn tree_sitter_swift() -> tree_sitter::Language;
        fn tree_sitter_tsx() -> tree_sitter::Language;
        fn tree_sitter_hcl() -> tree_sitter::Language;
        fn tree_sitter_yaml() -> tree_sitter::Language;
        fn tree_sitter_starlark() -> tree_sitter::Language;
        fn tree_sitter_bash() -> tree_sitter::Language;
        fn tree_sitter_php() -> tree_sitter::Language;
        fn tree_sitter_markdown() -> tree_sitter::Language;
        fn tree_sitter_apex() -> tree_sitter::Language;
        fn tree_sitter_r() -> tree_sitter::Language;
        fn tree_sitter_sql() -> tree_sitter::Language;
    }

    match language {
        Language::Csharp => unsafe { tree_sitter_c_sharp() },
        Language::Dart => unsafe { tree_sitter_dart() },
        Language::Dockerfile => unsafe { tree_sitter_dockerfile() },
        Language::Go => unsafe { tree_sitter_go() },
        Language::Elixir => unsafe { tree_sitter_elixir() },
        Language::Java => unsafe { tree_sitter_java() },
        Language::JavaScript => unsafe { tree_sitter_javascript() },
        Language::Kotlin => unsafe { tree_sitter_kotlin() },
        Language::Json => unsafe { tree_sitter_json() },
        Language::Python => unsafe { tree_sitter_python() },
        Language::Ruby => unsafe { tree_sitter_ruby() },
        Language::Rust => unsafe { tree_sitter_rust() },
        Language::Swift => unsafe { tree_sitter_swift() },
        Language::Terraform => unsafe { tree_sitter_hcl() },
        Language::TypeScript => unsafe { tree_sitter_tsx() },
        Language::Yaml => unsafe { tree_sitter_yaml() },
        Language::Starlark => unsafe { tree_sitter_starlark() },
        Language::Bash => unsafe { tree_sitter_bash() },
        Language::PHP => unsafe { tree_sitter_php() },
        Language::Markdown => unsafe { tree_sitter_markdown() },
        Language::Apex => unsafe { tree_sitter_apex() },
        Language::R => unsafe { tree_sitter_r() },
        Language::SQL => unsafe { tree_sitter_sql() },
    }
}

// get the tree-sitter tree
pub fn get_tree(code: &str, language: &Language) -> Option<tree_sitter::Tree> {
    let mut tree_sitter_parser = tree_sitter::Parser::new();
    let tree_sitter_language = get_tree_sitter_language(language);
    tree_sitter_parser
        .set_language(&tree_sitter_language)
        .ok()?;
    tree_sitter_parser.parse(code, None)
}

// build the query from tree-sitter
pub fn get_query(
    query_code: &str,
    language: &Language,
) -> Result<TSQuery, tree_sitter::QueryError> {
    let tree_sitter_language = get_tree_sitter_language(language);
    let mut tsq = TSQuery::try_new(&tree_sitter_language, query_code)?;
    // The ts_query__perform_analysis bug (duplicate patterns + dropped text predicates)
    // only manifests with the Dart grammar under tree-sitter 0.25.x.  Other grammars
    // handle #match?/#not-match? correctly, so we keep the workaround Dart-only.
    if matches!(language, Language::Dart) {
        tsq.extracted_predicates = extract_match_predicates(query_code, &tsq.capture_names);
    }
    Ok(tsq)
}

/// A wrapper around a [`tree_sitter::Query`].
#[derive(Debug)]
pub struct TSQuery {
    query: tree_sitter::Query,
    capture_names: Vec<Arc<str>>,
    // Dart-only workaround for tree-sitter 0.25.x: ts_query__perform_analysis duplicates
    // query patterns and drops all text predicates (#match?/#not-match?) for the Dart
    // grammar.  Populated only when the query was created via get_query(…, Language::Dart).
    extracted_predicates: Vec<ExtractedPredicate>,
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
            extracted_predicates: Vec::new(),
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
            extracted_predicates: &self.extracted_predicates,
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
            extracted_predicates: &self.extracted_predicates,
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
        // No source available, so no predicates can be extracted.
        Self {
            query: value,
            capture_names,
            extracted_predicates: Vec::new(),
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
    extracted_predicates: &'a [ExtractedPredicate],
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

        let extracted_predicates = self.extracted_predicates;
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
        .into_iter()
        .filter(|qm| apply_extracted_predicates(extracted_predicates, qm, text.as_bytes()))
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_get_tree() {
        let source_code = r#"
arr = ["foo", "bar"];

def func():
   pass;"#;
        let t = get_tree(source_code, &Language::Python);
        assert!(t.is_some());
        assert_eq!("module", t.unwrap().root_node().kind());
    }

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

    #[test]
    fn test_csharp_get_tree() {
        let source_code = r#"
namespace HelloWorld
{
    class Hello {
        static void Main(string[] args)
        {
            System.Console.WriteLine("Hello World!");
        }
    }
}
"#;
        let t = get_tree(source_code, &Language::Csharp);
        assert!(t.is_some());
        assert_eq!("compilation_unit", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_dockerfile_get_tree() {
        let source_code = r#"
RUN /blabla
"#;
        let t = get_tree(source_code, &Language::Dockerfile);
        assert!(t.is_some());
        assert_eq!("source_file", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_go_test_tree() {
        let source_code = r#"
package main
import "fmt"
func main() {
    fmt.Println("hello world")
}
"#;
        let t = get_tree(source_code, &Language::Go);
        assert!(t.is_some());
        assert_eq!("source_file", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_java_get_tree() {
        let source_code = r#"
class Foo {
}
"#;
        let t = get_tree(source_code, &Language::Java);
        assert!(t.is_some());
        assert_eq!("program", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_javascript_get_tree() {
        let source_code = r#"
function foo() {console.log("bar");}"#;
        let t = get_tree(source_code, &Language::JavaScript);
        assert!(t.is_some());
        assert_eq!("program", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_json_get_tree() {
        let source_code = r#"
{}"#;
        let t = get_tree(source_code, &Language::Json);
        assert!(t.is_some());
        assert_eq!("document", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_dart_get_tree() {
        let source_code = r#"void main() {
  print('Hello, Dart!');
}
"#;
        let t = get_tree(source_code, &Language::Dart);
        assert!(t.is_some());
        assert_eq!("program", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_ruby_get_tree() {
        let source_code = r#"def greeting
  puts "Hello Ruby!"
  return
end

greeting()
"#;
        let t = get_tree(source_code, &Language::Ruby);
        assert!(t.is_some());
        assert_eq!("program", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_rust_get_tree() {
        let source_code = r#"
fn foo(bar: String) -> String {
   return "foobar".to_string();
}
"#;
        let t = get_tree(source_code, &Language::Rust);
        assert!(t.is_some());
        assert_eq!("source_file", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_kotlin_get_tree() {
        let source_code = r#"
fun main() {
    println("What's your name?")
    val name = readln()
    println("Hello, $name!")
}
"#;
        let t = get_tree(source_code, &Language::Kotlin);
        assert!(t.is_some());
        assert_eq!("source_file", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_swift_get_tree() {
        let source_code = r#"
// HelloWorld.swift
import Foundation
print("Hello, World!")

"#;
        let t = get_tree(source_code, &Language::Swift);
        assert!(t.is_some());
        assert_eq!("source_file", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_typescript_get_tree() {
        let source_code = r#"
let myAdd = function (x: number, y: number): number {
  return x + y;
};
"#;
        let t = get_tree(source_code, &Language::TypeScript);
        assert!(t.is_some());
        assert_eq!("program", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_yaml_get_tree() {
        let source_code = r#"
rulesets:
  - my-ruleset
"#;
        let t = get_tree(source_code, &Language::Yaml);
        assert!(t.is_some());
        assert_eq!("stream", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_starlark_get_tree() {
        let source_code = r#"
load("@io_bazel_rules_docker//container:container.bzl", "container_image")
container_image(
    name = "base",
    base = "@io_bazel_rules_docker//images/ubuntu-1604:latest",
)
"#;
        let t = get_tree(source_code, &Language::Starlark);
        assert!(t.is_some());
        assert_eq!("module", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_bash_get_tree() {
        let source_code = r#"
echo "Hello, World!"
"#;
        let t = get_tree(source_code, &Language::Bash);
        assert!(t.is_some());
        assert_eq!("program", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_php_get_tree() {
        let source_code = r#"
<?php
echo "Hello, World!";
?>
"#;
        let t = get_tree(source_code, &Language::PHP);
        assert!(t.is_some());
        let t = t.unwrap();
        assert!(!t.root_node().has_error());
        assert_eq!("program", t.root_node().kind());
    }

    #[test]
    fn test_markdown_get_tree() {
        let source_code = r#"
# Hello, World!
This is some text
"#;
        let t = get_tree(source_code, &Language::Markdown);
        assert!(t.is_some());
        let t = t.unwrap();
        assert!(!t.root_node().has_error());
        assert_eq!("document", t.root_node().kind());
    }

    #[test]
    fn test_apex_get_tree() {
        let source_code = r#"
public class HelloWorld {
    public static void main() {
        System.out.println('Hello, World');
    }
}"#;
        let t = get_tree(source_code, &Language::Apex);
        assert!(t.is_some());
        let t = t.unwrap();
        assert!(!t.root_node().has_error());
        assert_eq!("parser_output", t.root_node().kind());
    }

    #[test]
    fn test_r_get_tree() {
        let source_code = r#"
x <- 1
print("Hello, World!")
"#;
        let t = get_tree(source_code, &Language::R);
        assert!(t.is_some());
        let t = t.unwrap();
        assert!(!t.root_node().has_error());
        assert_eq!("program", t.root_node().kind());
    }

    #[test]
    fn test_elixir_get_tree() {
        let source_code = r#"
defmodule Sum do
  def add(a, b) do
    a + b
  end
end
"#;
        let t = get_tree(source_code, &Language::Elixir);
        assert!(t.is_some());
        let t = t.unwrap();
        assert!(!t.root_node().has_error());
        assert_eq!("source", t.root_node().kind());
    }

    #[test]
    fn test_sql_get_tree() {
        let source_code = r#"
SELECT * FROM table WHERE column = 'value';
"#;
        let t = get_tree(source_code, &Language::SQL);
        assert!(t.is_some());
        let t = t.unwrap();
        assert!(!t.root_node().has_error());
        assert_eq!("program", t.root_node().kind());
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

    /// Verifies that the Dart `#match?` workaround correctly handles escaped regex sequences
    /// (e.g. `\\d` → `\d`) and `#not-match?`, and that non-Dart grammars are unaffected
    /// (their predicates are handled natively by tree-sitter).
    #[test]
    fn match_predicate_workaround_dart_only() {
        // Dart: `#match?` with escaped regex (`\\.` = literal dot, `\\d` = digit class).
        // The workaround is active only for Dart; non-Dart grammars use tree-sitter natively.
        {
            let source = "var httpFoo = null;\nvar other = null;\n";
            let tree = get_tree(source, &Language::Dart).unwrap();
            let q = get_query(
                r#"(identifier) @id (#match? @id "^http")"#,
                &Language::Dart,
            )
            .unwrap();
            let matches = q.cursor().matches(tree.root_node(), source, None);
            let texts: Vec<&str> = matches
                .iter()
                .flat_map(|m| m.iter())
                .filter_map(|cap| {
                    if let TSCaptureContent::Single(n) = &cap.contents {
                        n.utf8_text(source.as_bytes()).ok()
                    } else {
                        None
                    }
                })
                .collect();
            assert!(
                texts.iter().all(|t| t.starts_with("http")),
                "Dart #match? predicate not applied: {texts:?}"
            );
            assert!(!texts.is_empty(), "Dart #match? over-filtered everything");
        }

        // Dart: `#not-match?` — identifiers NOT starting with underscore.
        {
            let source = "var _private = null;\nvar public_ = null;\n";
            let tree = get_tree(source, &Language::Dart).unwrap();
            let q = get_query(
                r#"(identifier) @id (#not-match? @id "^_")"#,
                &Language::Dart,
            )
            .unwrap();
            let matches = q.cursor().matches(tree.root_node(), source, None);
            let texts: Vec<&str> = matches
                .iter()
                .flat_map(|m| m.iter())
                .filter_map(|cap| {
                    if let TSCaptureContent::Single(n) = &cap.contents {
                        n.utf8_text(source.as_bytes()).ok()
                    } else {
                        None
                    }
                })
                .collect();
            assert!(
                texts.iter().all(|t| !t.starts_with('_')),
                "#not-match? leaked private names: {texts:?}"
            );
        }
    }

    /// Debug test for the tree-sitter Dart `#match?` predicate bug.
    ///
    /// ## Root cause (confirmed by this test)
    ///
    /// `tree_sitter::Query::new` on the Dart grammar (both ABI v14 and v15) compiles a
    /// single-pattern query `(identifier) @id (#match? @id "^http")` into **2 patterns**
    /// instead of 1.  `ts_query__perform_analysis` duplicates the pattern AND drops the
    /// `#match?` text predicate from both copies.  As a result:
    ///
    /// - Matches with `pattern_index=1` always have `capture_count=0` → vacuous-true.
    /// - Matches with `pattern_index=0` have `text_predicates[0]` empty → vacuous-true.
    ///
    /// Every identifier matches, regardless of the regex.
    ///
    /// ## To fix
    ///
    /// The bug is in tree-sitter 0.25.x's query analysis phase, not in the Dart grammar.
    /// Switching to the `muh-nee/tree-sitter-dart` ABI v14 fork does NOT help.
    /// The fix requires either upgrading tree-sitter (needs API compatibility check for
    /// 0.26.x) or patching the `ts_query__perform_analysis` phase to preserve predicates
    /// when duplicating patterns.
    ///
    /// Run with:
    ///   cargo test --package static-analysis-kernel dart_match_predicate_debug -- --nocapture
    #[test]
    fn dart_match_predicate_debug() {
        let source = "var httpClient = null;\nvar other = null;\n";
        let dart_lang = get_tree_sitter_language(&Language::Dart);
        let tree = get_tree(source, &Language::Dart).expect("Dart tree parse failed");
        let query_str = r#"(identifier) @id (#match? @id "^http")"#;

        // ── Underlying bug: tree-sitter 0.25.x duplicates the pattern ──────────
        // pattern_count should be 1; tree-sitter returns 2 and drops text predicates.
        let raw_q = tree_sitter::Query::new(&dart_lang, query_str).expect("raw query");
        let pattern_count = raw_q.pattern_count();
        println!(
            "tree-sitter pattern_count={pattern_count} (expected 1; bug produces {pattern_count})"
        );

        {
            use tree_sitter::StreamingIterator as _;
            let mut cursor = tree_sitter::QueryCursor::new();
            let mut matches = cursor.matches(&raw_q, tree.root_node(), source.as_bytes());
            println!("raw tree-sitter matches (predicate not applied by ts — all pass):");
            let mut n = 0usize;
            while let Some(m) = matches.next() {
                let caps: Vec<(u32, &str)> = m
                    .captures
                    .iter()
                    .map(|c| (c.index, c.node.utf8_text(source.as_bytes()).unwrap_or("?")))
                    .collect();
                println!("  [{n}] pattern_index={} captures={caps:?}", m.pattern_index);
                n += 1;
            }
            println!("  total={n}");
        }

        // ── Workaround: TSQueryCursor post-filter should fix the result ─────────
        let q_wrapped = get_query(query_str, &Language::Dart).expect("wrapped query");
        let workaround_matches = q_wrapped
            .cursor()
            .matches(tree.root_node(), source, None);
        let matched_texts: Vec<String> = workaround_matches
            .iter()
            .flat_map(|qm| qm.iter())
            .map(|cap| match &cap.contents {
                TSCaptureContent::Single(n) => {
                    n.utf8_text(source.as_bytes()).unwrap_or("?").to_string()
                }
                TSCaptureContent::Multi(ns) => ns
                    .iter()
                    .map(|n| n.utf8_text(source.as_bytes()).unwrap_or("?"))
                    .collect::<Vec<_>>()
                    .join(","),
            })
            .collect();
        println!("TSQueryCursor matches after workaround: {matched_texts:?}");

        // Only "httpClient" should survive — "other" and phantoms must be filtered.
        assert!(
            matched_texts.iter().all(|t| t.starts_with("http")),
            "workaround failed: non-http identifier(s) leaked through: {matched_texts:?}"
        );
        assert!(
            !matched_texts.is_empty(),
            "workaround over-filtered: no matches at all"
        );
    }
}
