// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use deno_core::v8;
use graphviz_rust::dot_structures;
use std::borrow::{Borrow, Cow};
use std::collections::{HashMap, HashSet};

/// A wrapper around a [`graphviz_rust::Graph::DiGraph`]. This is only used in unit tests to specify
/// and assert on the structure of a graph.
#[derive(Debug, Clone)]
pub struct Digraph(dot_structures::Graph);

impl Digraph {
    /// Constructs a [`Self`] from the provided `input`.
    /// # Panics
    /// * Panics if `input` is not a strict digraph.
    /// * Panics if any [`dot_structures::Stmt`] in `input` isn't a node or an edge.
    pub fn new(input: dot_structures::Graph) -> Self {
        use dot_structures::*;
        let Graph::DiGraph { strict, stmts, .. } = &input else {
            panic!("graph should be a digraph");
        };
        assert!(strict, "should be \"strict\"");
        let all_valid_stmts = stmts
            .iter()
            .all(|stmt| matches!(stmt, Stmt::Node(..) | Stmt::Edge(..)));
        assert!(all_valid_stmts, "should only contain `node`s and `edge`s");
        Self(input)
    }

    /// Returns `true` if this graph is a subgraph of the provided `other`. A graph is considered
    /// a subgraph if the `other` has identical nodes and edges as this graph.
    pub fn is_subgraph_of(&self, other: impl Borrow<Self>) -> bool {
        self.difference(other).is_empty()
    }

    /// Returns the nodes and edges that are in `self`, but not in `other`.
    pub fn difference(&self, other: impl Borrow<Self>) -> Vec<dot_structures::Stmt> {
        use dot_structures::*;

        /// Returns a hash map of nodes and edges, using an arbitrary (but stable) key.
        fn normalize_stmts(graph: &Graph) -> HashMap<String, &Stmt> {
            fn attr_string(attributes: &[Attribute]) -> String {
                let mut attrs = attributes
                    .iter()
                    .map(|attr| format!("{}={}", attr.0, attr.1))
                    .collect::<Vec<_>>();
                attrs.sort();
                format!("[{}]", attrs.join(","))
            }

            digraph_stmts(graph)
                .iter()
                .map(|stmt| match stmt {
                    Stmt::Node(node) => (
                        format!("{}{}", node.id.0, attr_string(&node.attributes)),
                        stmt,
                    ),
                    Stmt::Edge(edge) => {
                        let EdgeTy::Pair(Vertex::N(src), Vertex::N(target)) = &edge.ty else {
                            unreachable!()
                        };
                        let (src, target, attrs) =
                            (&src.0, &target.0, attr_string(&edge.attributes));
                        (format!("{src}->{target}{attrs}"), stmt)
                    }
                    _ => unreachable!(),
                })
                .collect::<HashMap<_, _>>()
        }

        let self_stmts = normalize_stmts(&self.0);
        let other_stmts = normalize_stmts(&other.borrow().0);

        let mut diff = Vec::<Stmt>::new();
        for (key, &value) in &self_stmts {
            if !other_stmts.contains_key(key) {
                diff.push(value.clone());
            }
        }
        diff
    }

    /// Returns this graph in DOT form. Note that the nodes and edges are displayed in construction-order,
    /// which does not hold semantic meaning. Two [`Digraph`] can have a different `to_dot` output
    /// but represent the same graph.
    pub fn to_dot(&self) -> String {
        use graphviz_rust::printer::DotPrinter;
        self.0.print(&mut Default::default())
    }
}

impl PartialEq for Digraph {
    fn eq(&self, other: &Self) -> bool {
        self.difference(other).is_empty() && other.difference(self).is_empty()
    }
}

/// Returns the [`Stmt`](dot_structures::Stmt)s in a [`dot_structures::Graph::DiGraph`].
fn digraph_stmts(graph: &dot_structures::Graph) -> &[dot_structures::Stmt] {
    let dot_structures::Graph::DiGraph { stmts, .. } = graph else {
        panic!("graph should be a digraph");
    };
    stmts
}

// DOT attribute keys
const KIND: &str = "kind";

/// A graph edge storing a target [`VertexId`] and an [`EdgeKind`].
///
/// Internally, this is a bit-packed integer [`v8::Number`]:
/// ```text
///            49 bits           4 bits
/// |---------------------------|----|
///         targetVertexId       kind
/// ```
struct Edge(u32);

impl Edge {
    /// The number of bits used to represent the uint form of this enum.
    const KIND_BITS: u32 = 4;
    /// A bitmask to extract an `EdgeKind` from the bit-packed edge.
    const KIND_BIT_MASK: u32 = (1 << Self::KIND_BITS) - 1;

    /// Returns the target of this edge.
    pub fn target(&self) -> VertexId {
        VertexId(self.0 >> Self::KIND_BITS)
    }

    /// The type of edge this is.
    pub fn kind(&self) -> EdgeKind {
        EdgeKind::try_from_id((self.0 & Self::KIND_BIT_MASK) as usize)
            .expect("js should serialize PackedEdge correctly")
    }
}

/// The type of edge between two nodes in the [`Digraph`].
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum EdgeKind {
    Untyped = 0,
    Assignment,
    Dependence,
}

impl std::fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EdgeKind::Untyped => write!(f, "untyped"),
            EdgeKind::Assignment => write!(f, "assignment"),
            EdgeKind::Dependence => write!(f, "dependence"),
        }
    }
}

impl TryFrom<&str> for EdgeKind {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "untyped" => Ok(Self::Untyped),
            "assignment" => Ok(Self::Assignment),
            "dependence" => Ok(Self::Dependence),
            _ => Err(format!("invalid edge type `{value}`")),
        }
    }
}

impl EdgeKind {
    /// Creates a new `EdgeKind` if the provided `id` is valid.
    pub(crate) fn try_from_id(id: usize) -> Result<Self, String> {
        match id {
            i if i == EdgeKind::Untyped as usize => Ok(EdgeKind::Untyped),
            i if i == EdgeKind::Assignment as usize => Ok(EdgeKind::Assignment),
            i if i == EdgeKind::Dependence as usize => Ok(EdgeKind::Dependence),
            _ => Err(format!("invalid id {id}")),
        }
    }
}

/// A [`v8::Number`] used to store an id of a vertex in a [`Digraph`].
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
struct VertexId(u32);

impl std::fmt::Display for VertexId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.0)
    }
}

/// Returns the string form of a `dot_structures::Id`.
fn id_str(id: &dot_structures::Id) -> Cow<str> {
    use dot_structures::Id;
    match id {
        Id::Html(s) | Id::Plain(s) | Id::Anonymous(s) => Cow::Borrowed(s),
        Id::Escaped(s) => {
            let sans_quotes = &s[1..s.len() - 1];
            let mut chars = sans_quotes.chars();
            let mut unescaped = String::new();

            while let Some(ch) = chars.next() {
                unescaped.push(match ch {
                    '\\' => chars.next().expect("string should never end on `\\`"),
                    _ => ch,
                });
            }
            Cow::Owned(unescaped)
        }
    }
}

/// A [`dot_structures::Graph`] directly deserialized from v8, containing only the vertex and
/// edge information present in the v8 representation.
pub(crate) struct V8DotGraph {
    vertices: Vec<dot_structures::Node>,
    edges: Vec<dot_structures::Edge>,
}

impl V8DotGraph {
    /// Creates a new `V8DotGraph` from the provided `v8::Map`.
    /// # Panics
    /// Panics if deserialization is unsuccessful.
    pub fn new(scope: &mut v8::HandleScope, map: v8::Local<v8::Map>) -> Self {
        use dot_structures::*;
        use graphviz_rust::dot_generator::*;

        let mut vertices: Vec<Node> = vec![];
        let mut edges: Vec<Edge> = vec![];

        // VertexIds we discovered as the source of an edge.
        let mut known_sources = HashSet::<VertexId>::new();
        // VertexIds we discovered as the target of an edge.
        let mut known_targets = HashSet::<VertexId>::new();

        let map_arr = map.as_array(scope);
        let len = map_arr.length();
        for i in (0..len).step_by(2) {
            let key_idx = i;
            let val_idx = key_idx + 1;
            let source_vid = map_arr.get_index(scope, key_idx).unwrap();
            assert!(source_vid.is_number());
            let source_vid = source_vid.uint32_value(scope).unwrap();
            known_sources.insert(VertexId(source_vid));
            let adj_list =
                v8::Local::<v8::Array>::try_from(map_arr.get_index(scope, val_idx).unwrap())
                    .unwrap();
            vertices.push(node!(source_vid));

            let adj_len = adj_list.length();
            for j in 0..adj_len {
                let v8_packed_edge = adj_list.get_index(scope, j).unwrap();
                assert!(v8_packed_edge.is_number());
                let v8_packed_edge = v8_packed_edge.uint32_value(scope).unwrap();
                let packed_edge = Edge(v8_packed_edge);
                let target_vid = packed_edge.target();
                known_targets.insert(target_vid);

                let edge = edge!(node_id!(source_vid) => node_id!(target_vid), vec![attr![KIND, packed_edge.kind()]]);
                edges.push(edge);
            }
        }

        // Targets with no outgoing edges are sinks (and will not have been inserted as nodes yet).
        for &sink_vid in known_targets.difference(&known_sources) {
            vertices.push(node!(sink_vid));
        }

        Self { vertices, edges }
    }

    /// Converts this graph into a [`dot_structures::Graph`].
    #[rustfmt::skip]
    pub fn to_dot<T>(&self, name: impl Into<String>, vertex_transformer: T) -> dot_structures::Graph
    where
        for<'a> T: Fn(&'a dot_structures::Node) -> dot_structures::Node,
    {
        use dot_structures::*;
        // A cache storing the result of `vertex_transformer`'s mutation of a `dot_structures::NodeId`.
        let mut vertex_id_map = HashMap::<String, NodeId>::new();
        let vertices = self
            .vertices
            .iter()
            .map(|node| {
                let before_id = id_str(&node.id.0).to_string();
                let transformed = vertex_transformer(node);
                let after_id = transformed.id.clone();
                vertex_id_map.insert(before_id, after_id);
                transformed
            })
            .map(Stmt::Node)
            .collect::<Vec<_>>();
        let edges = self
            .edges
            .iter()
            .map(|edge| {
                // Edges remain the same, except the vertex ids they reference are updated to their transformed form.
                let mut cloned = edge.clone();
                let EdgeTy::Pair(Vertex::N(source), Vertex::N(target)) = &mut cloned.ty else { unreachable!(); };
                let new_source_id = vertex_id_map.get(id_str(&source.0).as_ref()).expect("edge should refer to known id").clone();
                let _ = std::mem::replace(source, new_source_id);
                let new_target_id = vertex_id_map.get(id_str(&target.0).as_ref()).expect("edge should refer to known id").clone();
                let _ = std::mem::replace(target, new_target_id);
                cloned
            })
            .map(Stmt::Edge)
            .collect::<Vec<_>>();

        Graph::DiGraph {
            id: Id::Plain(name.into()),
            strict: true,
            stmts: [vertices, edges].concat(),
        }
    }
}

/// Encodes the input as either a [`Plain`](dot_structures::Id::Plain) or [`Escaped`](dot_structures::Id::Escaped) id.
fn encode_id(input: impl AsRef<str>) -> dot_structures::Id {
    let input = input.as_ref();

    // (The char ranges below are from the official DOT language grammar spec)
    let needs_escape = input
        .chars()
        .any(|ch| !matches!(ch, '0'..='9' | 'a'..='z' | 'A'..='Z' | '_' ));
    if needs_escape {
        dot_structures::Id::Escaped(format!("\"{}\"", input.replace(r#"""#, r#"\""#)))
    } else {
        dot_structures::Id::Plain(input.to_string())
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::common::compile_script;
    use crate::analysis::ddsa_lib::js::flow::graph::{
        id_str, Digraph, Edge, EdgeKind, V8DotGraph, VertexId, KIND,
    };
    use crate::analysis::ddsa_lib::test_utils::{cfg_test_runtime, try_execute};
    use crate::analysis::ddsa_lib::JsRuntime;
    use deno_core::v8;
    use graphviz_rust::dot_structures;

    /// A newtype wrapper around a string vertex id.
    struct TestVertex(String);

    impl TestVertex {
        /// A mapping from a string name to an assigned id.
        /// It is used to specify human-friendly string vertex ids and have them transparently
        /// translated to and from a JavaScript numeric `VertexId`.
        /// (This is a hardcoded mapping for simplicity).
        const ID_MAPPING: &'static [(&'static str, VertexId)] = &[
            // Generic CST node vertices:
            ("v_1", VertexId(1)),
            ("v_2", VertexId(2)),
            ("v_3", VertexId(3)),
        ];

        /// Creates a new `TestVertex` from a DOT-specified id with the string format:
        /// ```text
        /// v_1  // Generic CST node vertex
        /// ```
        /// Panics if the vertex id is not pre-defined in [`Self::ID_MAPPING`].
        fn from_dot(dot_vertex_id: &str) -> Self {
            let is_known = Self::ID_MAPPING
                .iter()
                .any(|&(str_id, _)| str_id == dot_vertex_id);
            assert!(is_known, "vertex id `{dot_vertex_id}` must be predefined");
            Self(dot_vertex_id.to_string())
        }

        /// Converts this to a `dot_structures::Node`. A round-trip from [`Self::from_dot`] to this
        /// function will not lose any fundamental information.
        fn to_dot(&self) -> dot_structures::Node {
            use dot_structures::*;
            use graphviz_rust::dot_generator::*;
            // Reconstitute the string id.
            let &(str_id, _) = Self::ID_MAPPING
                .iter()
                .find(|(str_id, _)| str_id == &self.0)
                .unwrap();
            node!(str_id)
        }

        /// Returns the vertex id used by JavaScript.
        fn to_js_id(&self) -> VertexId {
            Self::ID_MAPPING
                .iter()
                .find(|&(str_id, _)| str_id == &self.0)
                .map(|(_, vid)| *vid)
                .unwrap()
        }

        /// Constructs a `Self` from a JavaScript vertex id.
        fn from_js_id(vertex_id: u32) -> Self {
            Self::ID_MAPPING
                .iter()
                .find(|&(_, vid)| VertexId(vertex_id) == *vid)
                .map(|(str_id, _)| Self(str_id.to_string()))
                .unwrap()
        }
    }

    /// Generates a snippet of JavaScript code that will construct a JavaScript `Digraph` based on the
    /// provided [`dot_structures::Graph`] and return the adjacency list.
    fn generate_graph_creation_js(graph: &dot_structures::Graph) -> String {
        use dot_structures::*;
        let Graph::DiGraph { stmts, .. } = graph else {
            unreachable!();
        };
        let add_edges = stmts
            .iter()
            .filter_map(|stmt| match stmt {
                Stmt::Edge(edge) => {
                    let EdgeTy::Pair(Vertex::N(source), Vertex::N(target)) = &edge.ty else {
                        unreachable!()
                    };
                    let source_vertex = TestVertex::from_dot(&id_str(&source.0));
                    let target_vertex = TestVertex::from_dot(&id_str(&target.0));
                    let edge_kind = edge
                        .attributes
                        .iter()
                        .find(|&attr| id_str(&attr.0) == KIND)
                        .map(|attr| EdgeKind::try_from(&*id_str(&attr.1)).unwrap())
                        .unwrap();
                    Some(format!(
                        // language=javascript
                        "graph.addTypedEdge({}, {}, {});",
                        source_vertex.to_js_id(),
                        target_vertex.to_js_id(),
                        edge_kind as u32
                    ))
                }
                _ => None,
            })
            .collect::<Vec<_>>();

        // language=javascript
        format!(
            "\
const graph = new Digraph();
{}
graph.adjacencyList;
",
            add_edges.join("\n")
        )
    }

    /// Deserialized `Digraph`s created from JavaScript adjacency lists.
    struct JsGraphs {
        /// The entire graph with all nodes.
        pub full: Digraph,
    }

    /// Builds a JavaScript `Digraph` from the provided `reference` and then deserializes it to
    /// a [`Digraph`] so it can be inspected.
    fn construct_js_graphs(reference: &str) -> JsGraphs {
        let mut rt = JsRuntime::try_new().unwrap();
        let reference_graph = graphviz_rust::parse(reference).unwrap();
        let js_script = generate_graph_creation_js(&reference_graph);
        let js_script = compile_script(&mut rt.v8_handle_scope(), &js_script).unwrap();

        let vertex_transformer = |node: &dot_structures::Node| -> dot_structures::Node {
            let vid = id_str(&node.id.0).parse::<u32>().unwrap();
            let vertex = TestVertex::from_js_id(vid);
            vertex.to_dot()
        };

        let full = rt
            .scoped_execute(
                &js_script,
                |sc, val| {
                    let full = v8::Local::<v8::Map>::try_from(val).unwrap();
                    let full = V8DotGraph::new(sc, full);
                    full.to_dot("full", vertex_transformer)
                },
                None,
            )
            .unwrap();

        let full = Digraph::new(full);
        JsGraphs { full }
    }

    /// Constructs a [`dot_structures::Graph`] and casts it to a `Digraph`.
    fn dot_graph(specification: &str) -> Digraph {
        let dot = graphviz_rust::parse(specification).unwrap();
        Digraph::new(dot)
    }

    /// The [`EdgeKind`] enum numbering should be consistent between Rust and JavaScript.
    #[test]
    fn edge_kind_js_synchronization() {
        let tests = [
            EdgeKind::Untyped,
            EdgeKind::Assignment,
            EdgeKind::Dependence,
        ];
        let mut rt = cfg_test_runtime();
        let scope = &mut rt.handle_scope();
        for rust_kind in tests {
            // (The name of the const exported from `graph.js`)
            let js_const = match rust_kind {
                EdgeKind::Untyped => "EDGE_UNTYPED",
                EdgeKind::Assignment => "EDGE_ASSIGNMENT",
                EdgeKind::Dependence => "EDGE_DEPENDENCE",
            };
            let js_value = try_execute(scope, &format!("{};", js_const)).unwrap();
            assert!(js_value.is_number());
            assert_eq!(rust_kind as u32, js_value.uint32_value(scope).unwrap());
        }
    }

    /// The Rust logic for unpacking an "Edge" JavaScript number is in sync with JavaScript.
    #[test]
    fn js_edge_rust_deserialize() {
        let mut rt = cfg_test_runtime();
        let sc = &mut rt.handle_scope();
        // language=javascript
        let js_code = "makeEdge(1234, EDGE_DEPENDENCE);";
        let packed_uint = try_execute(sc, js_code).unwrap();
        assert!(packed_uint.is_number());
        let packed_edge = Edge(packed_uint.uint32_value(sc).unwrap());
        assert_eq!(packed_edge.target(), VertexId(1234));
        assert_eq!(packed_edge.kind(), EdgeKind::Dependence);
    }

    /// The JavaScript logic for serializing and deserializing an "Edge" is correct.
    #[test]
    fn js_edge_js_ser_des() {
        let mut rt = cfg_test_runtime();
        let sc = &mut rt.handle_scope();
        // language=javascript
        let js_code = "\
const packed = makeEdge(1234, EDGE_DEPENDENCE);
`${getEdgeTarget(packed)}, ${getEdgeKind(packed)}`;
";
        let deserialized = try_execute(sc, js_code).unwrap().to_rust_string_lossy(sc);
        assert_eq!(deserialized, "1234, 2");
    }

    /// A vertex may not point to itself.
    #[test]
    fn graph_construction_assignment_identity() {
        // language=dot
        let attempted_graph = r#"
strict digraph {
    v_1
    v_2

    v_1 -> v_1 [kind=assignment]
    v_2 -> v_2 [kind=dependence]
}
        "#;
        // language=dot
        let expected_graph = r#"
strict digraph { }
        "#;

        let JsGraphs { full } = construct_js_graphs(attempted_graph);
        assert_eq!(full, dot_graph(expected_graph));
    }

    /// Graph edges are typed.
    #[test]
    fn graph_typed_edges() {
        // language=dot
        let original_graph = r#"
strict digraph {
    v_1
    v_2
    v_3

    v_2 -> v_3 [kind=dependence]
    v_1 -> v_2 [kind=assignment]
}
        "#;
        let expected_graph = original_graph;

        let JsGraphs { full } = construct_js_graphs(original_graph);
        assert_eq!(full, dot_graph(expected_graph));
    }

    /// Graph cycles are allowed.
    #[test]
    fn graph_cyclic_dependency() {
        // language=dot
        let original_graph = r#"
strict digraph {
    v_1
    v_2

    v_2 -> v_1 [kind=dependence]
    v_1 -> v_2  [kind=dependence]
}
        "#;
        let expected_graph = original_graph;

        let JsGraphs { full } = construct_js_graphs(original_graph);
        assert_eq!(full, dot_graph(expected_graph));
    }
}
