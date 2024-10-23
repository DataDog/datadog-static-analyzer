// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

// NOTE: Because units compiled with a `cfg(test)` scope are not accessible outside
//       their module, we work around this by exposing the following functions to all compilation profiles.
//       They should only be used in unit tests.

use crate::analysis::ddsa_lib::bridge::TsNodeBridge;
use crate::analysis::ddsa_lib::js::flow::graph::{
    digraph_stmts, encode_id, id_str, Digraph, EdgeKind, LocatedEdge, LocatedNode, V8DotGraph,
    VertexId, VertexKind, COL, CST_KIND, KIND, LINE, TEXT, V_KIND,
};
use crate::analysis::ddsa_lib::test_utils::TsTree;
use deno_core::v8;
use graphviz_rust::dot_structures;

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
                        k if k == V_KIND => continue,
                        k if k == TEXT => drop(text.insert(value.to_string())),
                        k if k == LINE => drop(line.insert(usize::from_str(&value).unwrap())),
                        k if k == COL => drop(col.insert(usize::from_str(&value).unwrap())),
                        k if k == CST_KIND => drop(cst_kind.insert(value.to_string())),
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
