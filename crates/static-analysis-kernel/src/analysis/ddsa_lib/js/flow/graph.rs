// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::bridge::TsNodeBridge;
use crate::analysis::ddsa_lib::test_utils::TsTree;
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
const TEXT: &str = "text";
const LINE: &str = "line";
const COL: &str = "col";
const CST_KIND: &str = "cstkind";
const V_KIND: &str = "vkind";
const NODE_ATTRS: &[&str] = &[TEXT, LINE, COL, CST_KIND, V_KIND];

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

/// An id of a vertex in a [`Digraph`], storing an [internal node id](VertexId::internal_id) and a [`VertexKind`].
///
/// Internally, this is a bit-packed integer [`v8::Number`]:
/// ```text
///            52 bits              1 bit
/// |------------------------------|-|
///         internalNodeId          kind
/// ```
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
struct VertexId(u32);

impl VertexId {
    /// The number of bits used to represent a [`VertexKind`].
    const KIND_BITS: u32 = 1;
    /// A bitmask to extract a [`VertexKind`] from a `VertexId`.
    const KIND_BIT_MASK: u32 = (1 << Self::KIND_BITS) - 1;

    /// Returns the kind of this vertex.
    pub fn kind(&self) -> VertexKind {
        VertexKind::try_from_id(self.0 & Self::KIND_BIT_MASK)
            .expect("js should serialize VertexId correctly")
    }

    /// Returns the internal node id for this vertex. This will return a [`ddsa_lib::common::NodeId`]
    /// if the vertex is a [`VertexKind::Cst`], or a phi node id if it's a [`VertexKind::Phi`].
    pub fn internal_id(&self) -> u32 {
        self.0 >> Self::KIND_BITS
    }

    /// Creates a `VertexId`, given a CST node id.
    pub const fn from_cst(id: u32) -> Self {
        Self(id << Self::KIND_BITS | VertexKind::Cst as u32)
    }

    /// Creates a `VertexId`, given a phi node id.
    pub const fn from_phi(id: u32) -> Self {
        Self(id << Self::KIND_BITS | VertexKind::Phi as u32)
    }
}

impl std::fmt::Display for VertexId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.0)
    }
}

/// An integer enum for the type of vertex in a [`Digraph`].
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum VertexKind {
    Cst = 0,
    Phi,
}

impl std::fmt::Display for VertexKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl TryFrom<&str> for VertexKind {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            Self::CST_STR => Ok(Self::Cst),
            Self::PHI_STR => Ok(Self::Phi),
            _ => Err(format!("invalid vertex kind `{value}`")),
        }
    }
}

impl VertexKind {
    const CST_STR: &'static str = "cst";
    const PHI_STR: &'static str = "phi";

    /// Creates a new `VertexKind` if the provided `id` is valid.
    pub(crate) fn try_from_id(id: u32) -> Result<Self, String> {
        match id {
            i if i == VertexKind::Cst as u32 => Ok(VertexKind::Cst),
            i if i == VertexKind::Phi as u32 => Ok(VertexKind::Phi),
            _ => Err(format!("invalid id {id}")),
        }
    }

    /// Returns the human-friendly string form of the `VertexKind`.
    pub fn as_str(&self) -> &str {
        match self {
            VertexKind::Cst => Self::CST_STR,
            VertexKind::Phi => Self::PHI_STR,
        }
    }

    /// Parses a DOT-specified node and returns its kind.
    pub fn try_from_dot(node: &dot_structures::Node) -> Result<Self, String> {
        for n in &node.attributes {
            let (key, value) = (id_str(&n.0), id_str(&n.1));
            match key.as_ref() {
                V_KIND if value == VertexKind::Cst.as_str() => return Ok(Self::Cst),
                V_KIND if value == VertexKind::Phi.as_str() => return Ok(Self::Phi),
                V_KIND => return Err(format!("invalid {V_KIND} `{value}`")),
                _ => {}
            }
        }
        Err(format!("can't find {V_KIND} within provided node"))
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

/// Creates a new `Digraph` from the provided [DOT Language] graph using a DSL that
/// allows CST/phi nodes to be searched for/specified succinctly. If provided, `root_node` will constrain
/// the search to the provided CST node and its children.
///
/// # Specifying Vertices
/// CST nodes are defined by specifying attributes that identify exactly one node within the syntax tree.
/// * `text`: an exact string match for the node's text, or `*` for any text _(default: <the DOT-specified node id>)_.
/// * `line`: an absolute line number for where the CST node is located in the source text.
/// * `col`: an absolute column number for where the CST node is located in the source text.
/// * `cstkind`: a CST node type for the node, or `*` for any type _(default: `identifier`)_.
///
/// Phi nodes should follow the id pattern of `phi{index}`, using a zero-based index (e.g. `phi0`, `phi1`)
/// that corresponds to the order in which it is created by the construction algorithm, and additionally
/// have the following attribute set to `phi`:
/// * `vkind`: a vertex kind (either `phi` or `cst`) _(default: `cst`)_.
///
/// For example, the following two are equivalent:
/// ```dot
/// strict digraph {
///     A1 [text=var_01,line=3]
///     A2 [text=var_01,line=5,col=22]
///     phi0 [vkind=phi]
///     var_02
///     1234 [cstkind="*"]
///     9876 [cstkind=decimal_integer_literal]
///
///     A1 -> 1234 [kind=assignment]
///     A2 -> 9876 [kind=assignment]
///     phi0 -> A1 [kind=dependence]
///     phi0 -> A2 [kind=dependence]
///     var_02 -> phi0 [kind=assignment]
/// }
/// // Equivalent:
/// strict digraph {
///     A1 [text=var_01,line=3,cstkind=identifier,vkind=cst]
///     A2 [text=var_01,line=5,col=22,cstkind=identifier,vkind=cst]
///     phi0 [vkind=phi]
///     var_02 [text=var_02,cstkind=identifier,vkind=cst]
///     1234 [text=1234,cstkind="*",vkind=cst]
///     9876 [text=9876,cstkind=decimal_integer_literal,vkind=cst]
///
///     A1 -> 1234 [kind=assignment]
///     A2 -> 9876 [kind=assignment]
///     phi0 -> A1 [kind=dependence]
///     phi0 -> A2 [kind=dependence]
///     var_02 -> phi0 [kind=assignment]
/// }
/// ```
/// [DOT Language]: https://graphviz.org/doc/info/lang.html
///
/// # Panics
/// Panics if any configuration is not as-expected or if any digraph CST node does not have
/// exactly 1 matching tree-sitter node.
pub fn cst_dot_digraph(
    dot: &str,
    ts_tree: &TsTree,
    root_node: Option<tree_sitter::Node>,
) -> Digraph {
    use dot_structures::*;

    let graph = graphviz_rust::parse(dot).unwrap();
    let stmts = digraph_stmts(&graph);

    let tree = ts_tree.tree();
    let candidates = TsTree::preorder_nodes(root_node.unwrap_or(tree.root_node()))
        .iter()
        .map(|&node| LocatedNode::new_cst(node, ts_tree.text(node)))
        .collect::<Vec<_>>();

    // The `String` in the tuple is the original ID of the vertex (as specified in the DOT).
    // Because we normalize all vertices to have a canonical vertex id, we use the original id as
    // a key to map it to its canonical form.
    let located: Vec<(LocatedNode, String)> = stmts
        .iter()
        .filter_map(|stmt| {
            if let Stmt::Node(node) = stmt {
                let attrs = NodeSearchAttrs::from_vertex(node);
                let original_text = id_str(&node.id.0).to_string();
                let located = match attrs {
                    NodeSearchAttrs::Phi => {
                        // Because phi nodes have no obvious serialization of a unique name (unlike CST nodes),
                        // despite the coupling with the graph construction algorithm, it vastly reduces
                        // implementation complexity to require a tests to specify the exact phi id in the DOT.
                        let num_id = original_text
                            .split_once("phi")
                            .and_then(|(pre, id)| {
                                if !pre.is_empty() {
                                    return None;
                                }
                                id.parse::<u32>().ok()
                            })
                            .expect("phi node id should have correct format: `phi{index}`");
                        let phi = LocatedNode::new_phi(num_id);
                        // (A lightweight "test" to keep this logic in sync with `canonical_id`).
                        assert_eq!(original_text, phi.canonical_id());
                        phi
                    }
                    NodeSearchAttrs::Cst { .. } => locate_node(attrs, &candidates),
                };
                Some((located, original_text))
            } else {
                None
            }
        })
        .collect();

    let edges = stmts
        .iter()
        .filter_map(|stmt| {
            if let Stmt::Edge(edge) = stmt {
                let EdgeTy::Pair(Vertex::N(source), Vertex::N(target)) = &edge.ty else {
                    panic!("edge should be between two `node`s")
                };
                assert_eq!(id_str(&edge.attributes[0].0), KIND);
                let kind = EdgeKind::try_from(&*id_str(&edge.attributes[0].1)).unwrap();
                assert_eq!(edge.attributes.len(), 1, "edge should only have 1 attr");

                // Locate the node based on the original id:
                let source_id = id_str(&source.0);
                let source = located.iter().find(|&(_, id)| &source_id == id);
                let (source, _) = source
                    .unwrap_or_else(|| panic!("edge-declared node `{source_id}` should exist"));
                let target_id = id_str(&target.0);
                let target = located.iter().find(|&(_, id)| &target_id == id);
                let (target, _) = target
                    .unwrap_or_else(|| panic!("edge-declared node `{target_id}` should exist"));
                let located = LocatedEdge {
                    source: *source,
                    target: *target,
                    kind,
                };
                Some(Stmt::Edge(Edge::from(located)))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let nodes = located
        .into_iter()
        .map(|(located, _)| Stmt::Node(Node::from(located)))
        .collect::<Vec<_>>();

    Digraph::new(Graph::DiGraph {
        id: Id::Plain("cst_dot".to_string()),
        strict: true,
        stmts: [nodes, edges].concat(),
    })
}

/// Converts a JavaScript Map<VertexId, PackedEdge[]> to a `FlowDigraph`.
///
/// # Panics
/// Panics if deserialization is unsuccessful.
pub(crate) fn cst_v8_digraph(
    name: &str,
    scope: &mut v8::HandleScope,
    map: v8::Local<v8::Map>,
    ts_tree: &TsTree,
    bridge: &TsNodeBridge,
) -> Digraph {
    // Transformation:
    // If `VertexKind::CST`: constructs a dot node from metadata from the `TsNodeBridge` and `ts_tree`.
    // If `VertexKind::Phi`: constructs a dot node from the internal id.
    let transform_vertex = |node: &dot_structures::Node| -> dot_structures::Node {
        let vid = VertexId(id_str(&node.id.0).parse::<u32>().unwrap());
        let located = match vid.kind() {
            VertexKind::Cst => {
                let raw = bridge.get_raw(vid.internal_id()).unwrap();
                // This is only used in tests, however...
                // Safety:
                // Given that the `ts_tree` provided owns the underlying `tree_sitter::Tree` that
                // the bridge's `RawTSNode`s are referencing, we know the tree is alive and that
                // the memory is still allocated.
                let ts_node = unsafe { raw.to_node() };
                LocatedNode::new_cst(ts_node, ts_tree.text(ts_node))
            }
            VertexKind::Phi => LocatedNode::new_phi(vid.internal_id()),
        };
        located.into()
    };

    let v8_dot_graph = V8DotGraph::new(scope, map);
    Digraph::new(v8_dot_graph.to_dot(name, transform_vertex))
}

/// Searches a list of candidates to find a `LocatedNode` that matches the [`NodeSearchAttrs::Cst`].
///
/// # Panics
/// Panics if the number of matches is not exactly 1 or if the `attrs` is not `NodeSearchAttrs::CST`.
#[rustfmt::skip]
fn locate_node<'a>(
    attrs: NodeSearchAttrs,
    candidates: &[LocatedNode<'a>],
) -> LocatedNode<'a> {
    let NodeSearchAttrs::Cst { text,  line, col, cst_kind } = &attrs else {
        panic!("attrs should be `NodeSearchAttrs::CST`");
    };
    let mut located: Option<LocatedNode> = None;
    for &cand in candidates {
        let LocatedNode::Cst { text: cand_text, line: cand_line, col: cand_col, cst_kind: cand_cst_kind } = cand else {
            panic!("candidate should be `LocatedNode::CST`");
        };
        if text.as_ref().map_or(true, |text| text == "*" || cand_text == text)
            && line.map_or(true, |line| cand_line == line)
            && col.map_or(true, |col| cand_col == col)
            && cst_kind.as_ref().map_or(true, |ty| ty == "*" || cand_cst_kind == ty)
        {
            if let Some(prev) = located.replace(cand) {
                panic!("two CST nodes matched {:?}: ({:?}, {:?})", attrs, prev, cand);
            }
        }
    }
    located.unwrap_or_else(|| panic!("{:?} should have matched", attrs))
}

/// Search metadata to identify a vertex.
#[derive(Debug, Clone)]
enum NodeSearchAttrs {
    Phi,
    Cst {
        text: Option<String>,
        line: Option<usize>,
        col: Option<usize>,
        cst_kind: Option<String>,
    },
}

impl NodeSearchAttrs {
    /// Parses a `NodeSearchAttrs` from a `dot_structured::Node`. Panics if the node
    /// is improperly formatted.
    fn from_vertex(node: &dot_structures::Node) -> Self {
        use std::str::FromStr;

        let mut vertex_kind: Option<VertexKind> = None;
        for n in &node.attributes {
            let (key, value) = (id_str(&n.0), id_str(&n.1));
            if key == V_KIND {
                let _ = vertex_kind.insert(
                    VertexKind::try_from(value.as_ref())
                        .expect("caller should provide valid value"),
                );
            }
        }
        // Default to CST node
        let vertex_kind = vertex_kind.unwrap_or(VertexKind::Cst);

        let mut text: Option<String> = None;
        let mut line: Option<usize> = None;
        let mut col: Option<usize> = None;
        let mut cst_kind: Option<String> = None;

        for n in &node.attributes {
            let (key, value) = (id_str(&n.0), id_str(&n.1));
            match vertex_kind {
                VertexKind::Cst => {
                    match key.as_ref() {
                        V_KIND => continue,
                        TEXT => drop(text.insert(value.to_string())),
                        LINE => drop(line.insert(usize::from_str(&value).unwrap())),
                        COL => drop(col.insert(usize::from_str(&value).unwrap())),
                        CST_KIND => drop(cst_kind.insert(value.to_string())),
                        _ => panic!("cst node: unexpected attribute `{key}`"),
                    };
                }
                VertexKind::Phi => {
                    if key != V_KIND {
                        panic!("phi node: unexpected attribute `{key}`");
                    }
                }
            }
        }

        match vertex_kind {
            VertexKind::Cst => {
                // Defaults
                let _ = text.get_or_insert_with(|| id_str(&node.id.0).to_string());
                let _ = cst_kind.get_or_insert_with(|| "identifier".to_string());

                Self::Cst {
                    text,
                    line,
                    col,
                    cst_kind,
                }
            }
            VertexKind::Phi => Self::Phi,
        }
    }
}

/// A located CST or phi node, along with all metadata needed to construct a [`dot_structures::Node`].
#[derive(Debug, Copy, Clone)]
enum LocatedNode<'a> {
    Phi {
        id: u32,
    },
    Cst {
        text: &'a str,
        line: usize,
        col: usize,
        cst_kind: &'static str,
    },
}

/// A directed edge from a source [`LocatedNode`] to a target.
#[derive(Debug, Copy, Clone)]
struct LocatedEdge<'a> {
    source: LocatedNode<'a>,
    target: LocatedNode<'a>,
    kind: EdgeKind,
}

impl From<LocatedEdge<'_>> for dot_structures::Edge {
    fn from(value: LocatedEdge<'_>) -> Self {
        use graphviz_rust::dot_generator::*;
        use graphviz_rust::dot_structures::*;
        edge!(
            NodeId(encode_id(value.source.canonical_id()), None) => NodeId(encode_id(value.target.canonical_id()), None),
            vec![attr!(KIND, value.kind.to_string())]
        )
    }
}

impl<'a> LocatedNode<'a> {
    /// Constructs a new `LocatedNode` from a tree-sitter node.
    fn new_cst(node: tree_sitter::Node<'a>, text: &'a str) -> LocatedNode<'a> {
        Self::Cst {
            text,
            line: node.start_position().row + 1,
            col: node.start_position().column + 1,
            cst_kind: node.kind(),
        }
    }

    /// Constructs a new `LocatedNode` from a phi node id.
    fn new_phi(id: u32) -> LocatedNode<'a> {
        Self::Phi { id }
    }

    /// A canonical id for this node.
    fn canonical_id(&self) -> String {
        match *self {
            LocatedNode::Phi { id } => format!("phi{id}"),
            LocatedNode::Cst {
                text, line, col, ..
            } => format!("{}:{}:{}", text, line, col),
        }
    }

    fn kind(&self) -> VertexKind {
        match self {
            LocatedNode::Phi { .. } => VertexKind::Phi,
            LocatedNode::Cst { .. } => VertexKind::Cst,
        }
    }
}

impl From<LocatedNode<'_>> for dot_structures::Node {
    #[rustfmt::skip]
    fn from(value: LocatedNode<'_>) -> Self {
        use dot_structures::*;
        use graphviz_rust::dot_generator::*;
        let mut attrs = match value {
            LocatedNode::Phi { .. } => vec![attr!("shape", "diamond")],
            LocatedNode::Cst { text, line, col, cst_kind } => vec![
                Attribute(id!(TEXT), encode_id(text)),
                attr!(LINE, line),
                attr!(COL, col),
                attr!(CST_KIND, cst_kind),
            ]
        };
        attrs.push(attr!(V_KIND, value.kind()));
        Node::new(NodeId(encode_id(value.canonical_id()), None), attrs)
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
        let mut text = input.replace("\"", "\\\"");
        text = text.replace("\r\n", "\\r\\n");
        text = text.replace("\n", "\\n");
        dot_structures::Id::Escaped(format!("\"{}\"", text))
    } else {
        dot_structures::Id::Plain(input.to_string())
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::common::compile_script;
    use crate::analysis::ddsa_lib::js::flow::graph::{
        id_str, Digraph, Edge, EdgeKind, V8DotGraph, VertexId, VertexKind, KIND,
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
            ("v_1", VertexId::from_cst(1)),
            ("v_2", VertexId::from_cst(2)),
            ("v_3", VertexId::from_cst(3)),
            // Phi nodes
            ("phi0", VertexId::from_phi(0)),
        ];

        /// Creates a new `TestVertex` from a DOT-specified id with the string format:
        /// ```text
        /// v_1  // Generic CST node vertex
        /// phi0 // Phi node vertex
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
        /// The transposed version of `full`.
        pub full_transposed: Digraph,
    }

    /// Builds a JavaScript `Digraph` from the provided `reference` and then deserializes it to
    /// a [`Digraph`] so it can be inspected.
    fn construct_js_graphs(reference: &str) -> JsGraphs {
        let mut rt = JsRuntime::try_new().unwrap();
        let reference_graph = graphviz_rust::parse(reference).unwrap();
        let mut js_script = generate_graph_creation_js(&reference_graph);
        // language=javascript
        js_script += "\
[graph.adjacencyList, transpose(graph.adjacencyList)];
";
        let js_script = compile_script(&mut rt.v8_handle_scope(), &js_script).unwrap();

        let vertex_transformer = |node: &dot_structures::Node| -> dot_structures::Node {
            let vid = id_str(&node.id.0).parse::<u32>().unwrap();
            let vertex = TestVertex::from_js_id(vid);
            vertex.to_dot()
        };

        let (full, full_transposed) = rt
            .scoped_execute(
                &js_script,
                |sc, val| {
                    let arr = v8::Local::<v8::Array>::try_from(val).unwrap();
                    let full =
                        v8::Local::<v8::Map>::try_from(arr.get_index(sc, 0).unwrap()).unwrap();
                    let full = V8DotGraph::new(sc, full);
                    let full_transposed =
                        v8::Local::<v8::Map>::try_from(arr.get_index(sc, 1).unwrap()).unwrap();
                    let full_transposed = V8DotGraph::new(sc, full_transposed);
                    (
                        full.to_dot("full", vertex_transformer),
                        full_transposed.to_dot("full_transposed", vertex_transformer),
                    )
                },
                None,
            )
            .unwrap();

        let full = Digraph::new(full);
        let full_transposed = Digraph::new(full_transposed);
        JsGraphs {
            full,
            full_transposed,
        }
    }

    /// Constructs a [`dot_structures::Graph`] and casts it to a `Digraph`.
    fn dot_graph(specification: &str) -> Digraph {
        let dot = graphviz_rust::parse(specification).unwrap();
        Digraph::new(dot)
    }

    /// The [`VertexKind`] enum numbering should be consistent between Rust and JavaScript.
    #[test]
    fn vertex_kind_js_synchronization() {
        let tests = [VertexKind::Cst, VertexKind::Phi];
        let mut rt = cfg_test_runtime();
        let scope = &mut rt.handle_scope();
        for rust_kind in tests {
            let js_const = match rust_kind {
                VertexKind::Cst => "VERTEX_CST",
                VertexKind::Phi => "VERTEX_PHI",
            };
            let js_value = try_execute(scope, &format!("{};", js_const)).unwrap();
            assert!(js_value.is_number());
            assert_eq!(rust_kind as u32, js_value.uint32_value(scope).unwrap());
        }
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
        let cases = [
            (VertexId::from_cst(1234), VertexKind::Cst),
            (VertexId::from_phi(1234), VertexKind::Phi),
        ];
        for (vid, vkind) in cases {
            // language=javascript
            let js_code = format!("makeEdge({vid}, EDGE_DEPENDENCE);",);
            let packed_uint = try_execute(sc, &js_code).unwrap();
            assert!(packed_uint.is_number());
            let edge = Edge(packed_uint.uint32_value(sc).unwrap());
            assert_eq!(edge.kind(), EdgeKind::Dependence);
            assert_eq!(edge.target().internal_id(), 1234);
            assert_eq!(edge.target().kind(), vkind);
        }
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

        let JsGraphs { full, .. } = construct_js_graphs(attempted_graph);
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

        let JsGraphs { full, .. } = construct_js_graphs(original_graph);
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

        let JsGraphs { full, .. } = construct_js_graphs(original_graph);
        assert_eq!(full, dot_graph(expected_graph));
    }

    /// Vertices can be phi nodes.
    #[test]
    fn graph_phi_vertices() {
        // language=dot
        let original_graph = r#"
strict digraph {
    v_1
    v_2
    v_3
    phi0

    phi0 -> v_3  [kind=dependence]
    phi0 -> v_2  [kind=dependence]
    v_1  -> phi0 [kind=dependence]
}
        "#;
        let expected_graph = original_graph;

        let JsGraphs { full, .. } = construct_js_graphs(original_graph);
        assert_eq!(full, dot_graph(expected_graph));
    }

    /// The `findTaintFlows` function properly traverses a graph and returns all possible flows.
    /// Phi nodes are preserved. Cycles are handled by ignoring the entire path.
    #[test]
    fn find_taint_flows_all_paths() {
        let mut rt = JsRuntime::try_new().unwrap();
        // language=js
        let js_code = "\
// A helper function to construct a dependence edge.
const cst = (id) => _asVertexId(id, VERTEX_CST);
const phi = (id) => _asVertexId(id, VERTEX_PHI);
const edge = (target) => {
    return makeEdge(target, EDGE_DEPENDENCE);
}

const adjList = new Map([
    [cst(1), [edge(cst(2))]],
    [cst(2), [edge(cst(3)), edge(cst(5))]],
    [cst(3), [edge(cst(4))]],
    [cst(5), [edge(phi(0))]],
    // Phi behavior: pointing to another phi
    [phi(0), [edge(cst(7)), edge(phi(1)), edge(cst(10))]],
    [cst(7), [edge(cst(9))]],
    // Phi behavior pointing to A) a non-cyclic vertex, B) a cyclic vertex
    [phi(1), [edge(cst(8)), edge(cst(10))]],
    [cst(10), [/* cycle */ edge(cst(2))]],
]);


const vidPaths = _findTaintFlows(adjList, cst(1), false).map((flow) => {
    return flow._vidPath.map((vid) => {
        const kindStr = vertexKind(vid) === VERTEX_CST ? 'cst' : 'phi';
        return `${kindStr}(${internalId(vid)})`;
    });
});
const serialized = vidPaths.map((flow) => DDSA_Console.stringify(flow)).join('\\n');
serialized;
";
        let js_code = compile_script(&mut rt.v8_handle_scope(), js_code).unwrap();
        let res = rt
            .scoped_execute(&js_code, |sc, value| value.to_rust_string_lossy(sc), None)
            .unwrap();
        let js_flows = res.lines().collect::<Vec<_>>();

        let expected = vec![
            r#"["cst(1)","cst(2)","cst(3)","cst(4)"]"#,
            r#"["cst(1)","cst(2)","cst(5)","phi(0)","cst(7)","cst(9)"]"#,
            r#"["cst(1)","cst(2)","cst(5)","phi(0)","phi(1)","cst(8)"]"#,
        ];
        assert_eq!(js_flows, expected);
    }

    /// The graph can be transposed.
    #[test]
    fn graph_transpose() {
        // language=dot
        let original_graph = r#"
strict digraph {
    v_1
    v_2
    v_3

    v_2 -> v_3 [kind=assignment]
    v_1 -> v_3 [kind=dependence]
    v_1 -> v_2 [kind=dependence]
}
        "#;
        let expected_graph = r#"
strict digraph {
    v_1
    v_2
    v_3

    v_3 -> v_2 [kind=assignment]
    v_3 -> v_1 [kind=dependence]
    v_2 -> v_1 [kind=dependence]
}
        "#;
        let JsGraphs {
            full_transposed, ..
        } = construct_js_graphs(original_graph);
        assert_eq!(full_transposed, dot_graph(expected_graph));
    }
}
