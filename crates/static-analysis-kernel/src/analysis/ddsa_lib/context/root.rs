// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::RawTSNode;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

/// A stateful struct containing metadata about a ddsa rule execution.
#[derive(Debug, Default)]
pub struct RootContext {
    /// The tree-sitter tree.
    //  NOTE: Despite the tree-sitter C library implementing `Tree` as a reference-counting pointer,
    //        we use an `Arc` here so that we can easily check tree equivalence (when a `tree_sitter::Tree`
    //        is cloned, the root_node does not have the same memory address).
    tree: Option<Arc<tree_sitter::Tree>>,
    /// The source string that was parsed by tree-sitter to generate `tree`.
    tree_text: Option<Arc<str>>,
    /// A filename associated with a rule execution.
    filename: Option<Arc<str>>,

    /// A map from a tree-sitter node's [`id`](tree_sitter::Node::id) (the memory address of the
    /// C struct in tree-sitter's address space) to its parent in [`RawTSNode`] form.
    ///
    /// Tree-sitter nodes do not contain a link to their parent, but they do contain a link to their children.
    /// (via the "subtree" pointer). Thus, to get the parent of an arbitrary `Node A`, we must
    /// traverse down the tree from the root until we reach a node that has `Node A` as a child.
    ///
    /// An expected access pattern is for the JavaScript runtime to request a traversal _up_ the tree
    /// (i.e. request a node's parent, and then its parent's parent, and so on). Without a cache,
    /// this has `O(D^2)` time complexity (`D` being the depth of the original node within the tree).
    /// This cache reduces that time complexity to `O(D)` (costing `O(D)` space complexity: 8 + 32 == 40 bytes per relationship).
    parent_map: RefCell<HashMap<usize, RawTSNode>>,
    /// A counter for how many times a tree traversal was triggered in `get_ts_node_parent`.
    #[cfg(test)]
    _cfg_test_tree_traversal_count: std::cell::Cell<usize>,
}

impl RootContext {
    /// Returns a reference to the text used to generate underlying `tree_sitter::Tree`, if it exists.
    pub fn get_text(&self) -> Option<&str> {
        self.tree_text.as_ref().map(AsRef::as_ref)
    }

    /// Assigns the provided text string to the context. If an existing text string was assigned, it
    /// will be returned as `Some(text)`.
    pub fn set_text(&mut self, text: Arc<str>) -> Option<Arc<str>> {
        Option::replace(&mut self.tree_text, text)
    }

    /// Returns a reference to the underlying [`tree_sitter::Tree`], if it exists.
    pub fn get_tree(&self) -> Option<&Arc<tree_sitter::Tree>> {
        self.tree.as_ref()
    }

    /// Assigns the provided `tree_sitter::Tree` to the context. If an existing tree was assigned, it
    /// will be returned as `Some(tree)`.
    pub fn set_tree(&mut self, tree: Arc<tree_sitter::Tree>) -> Option<Arc<tree_sitter::Tree>> {
        self.parent_map.borrow_mut().clear();
        Option::replace(&mut self.tree, tree)
    }

    /// Returns a reference to the filename assigned to the context.
    pub fn get_filename(&self) -> Option<&str> {
        self.filename.as_ref().map(AsRef::as_ref)
    }

    /// Assigns the provided filename to the context. If an existing filename was assigned, it
    /// will be returned as `Some(filename)`.
    pub fn set_filename(&mut self, filename: Arc<str>) -> Option<Arc<str>> {
        Option::replace(&mut self.filename, filename)
    }

    /// Returns the parent node of the provided child.
    ///
    /// # Returns
    /// **If the provided `node` is a valid node within the current tree:**
    /// * The node is not the tree root -> `Some(parent_node)`.
    /// * The node is the tree root -> `None`.
    ///
    /// **If the provided `node` is not a valid node within the current tree:**
    /// * Always -> `None`
    ///
    /// Note that the caller is tasked with ensuring the `tree_sitter::Node` is for the current
    /// tree, as no distinction is made between a node that isn't part of the tree and a
    /// node that is the root of the tree (they both return `None`).
    pub(crate) fn get_ts_node_parent(&self, node: tree_sitter::Node) -> Option<RawTSNode> {
        let tree = self
            .tree
            .as_ref()
            .expect("the tree should have already been init");
        let mut current_node = tree.root_node();
        // The tree's root has no parent
        if node.id() == current_node.id() {
            return None;
        }

        let mut parent_map = self.parent_map.borrow_mut();
        // If we've cached the incoming `node`, we've already verified that it originated from the
        // current `tree` because we have previously traversed and identified its child.
        if let Some(&raw_parent) = parent_map.get(&node.id()) {
            // Safety:
            // * fn `get_ts_node_parent` is the only mutator that adds to this `parent_map`, and the method
            //   by which it does this is to use [`tree_sitter::ffi::ts_node_child_containing_descendant`],
            //   which we trust to return only a valid child.
            // * fn `set_tree` clears the `parent_map` cache, so all `RawTSNode` must be for the current tree.
            return Some(raw_parent);
        }

        ///// Test hook
        #[cfg(test)]
        {
            // Increment the counter, as we're going to traverse the tree.
            let current_count = &self._cfg_test_tree_traversal_count.get();
            self._cfg_test_tree_traversal_count.set(current_count + 1);
        }
        /////

        let mut depth = 0;
        while let Some(child) = current_node.child_containing_descendant(node) {
            // Cache the relationship discovered as a side effect of traversing down from the root.
            // Note that because the `child_containing_descendant` API filter its output, we
            // only end up caching the path directly from the root to this node.
            //
            // (This key will already be populated if the requested node is a child of a
            // node previously discovered via walking the ancestor chain)
            let _ = parent_map.insert(child.id(), RawTSNode::new(current_node));
            // Traverse this child
            current_node = child;
            depth += 1;
            // We'll never iterate past the `node` parent, so `current_node` can never be `node`.
            debug_assert_ne!(node.id(), current_node.id());
        }
        // If the `depth` is 0, the passed in `node` didn't originate from `tree`.
        if depth == 0 {
            return None;
        }

        // Otherwise at depth > 0, if there is no child that contains the descendent,
        // the `current_node` must be the parent of `node`.
        let raw_node = RawTSNode::new(current_node);
        // Cache the final relationship. (This key will already be populated if the requested
        // node is a child of a node previously discovered via walking the ancestor chain).
        let _ = parent_map.insert(node.id(), raw_node);

        Some(raw_node)
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::RootContext;
    use crate::analysis::tree_sitter::get_tree;
    use crate::model::common::Language;
    use std::collections::HashMap;
    use std::sync::Arc;

    /// Source code to parse using the JavaScript grammar, used in the [`RootContext::get_ts_node_parent`] tests.
    const PARENT_CODE: &str = "function echo() { /* code */ }";

    /// Source code to parse, used for tests that require two different trees.
    const PARENT_CODE_2: &str = "const foxtrot = () => { /* different */ };";

    fn setup_parent_test(code: &str) -> (RootContext, Arc<tree_sitter::Tree>) {
        let mut ctx = RootContext::default();
        let source: Arc<str> = Arc::from(code);
        let tree = Arc::new(get_tree(source.as_ref(), &Language::JavaScript).unwrap());
        ctx.set_tree(Arc::clone(&tree));
        ctx.set_text(Arc::clone(&source));
        (ctx, tree)
    }

    /// A shorthand function to return the _named_ child at the given index.
    fn n_child(node: tree_sitter::Node, index: usize) -> tree_sitter::Node {
        node.named_child(index).unwrap()
    }

    /// (Assertion included to alert if upstream tree-sitter grammar unexpectedly alters metadata)
    #[test]
    fn ts_grammar_assertion() {
        let tree_1 = get_tree(PARENT_CODE, &Language::JavaScript).unwrap();
        let expected_1 = "(program (function_declaration name: (identifier) parameters: (formal_parameters) body: (statement_block (comment))))";
        assert_eq!(expected_1, tree_1.root_node().to_sexp(), "broken invariant");

        let tree_2 = get_tree(PARENT_CODE_2, &Language::JavaScript).unwrap();
        let expected_2 = "(program (lexical_declaration (variable_declarator name: (identifier) value: (arrow_function parameters: (formal_parameters) body: (statement_block (comment))))))";
        assert_eq!(expected_2, tree_2.root_node().to_sexp(), "broken invariant");
    }

    /// A node's parent should be able to be retrieved
    #[test]
    fn get_ts_node_parent() {
        let (ctx, tree) = setup_parent_test(PARENT_CODE);

        // Manually choose the (statement_block) node.
        let stmt = n_child(n_child(tree.root_node(), 0), 2);
        assert_eq!(stmt.kind(), "statement_block");

        // The parent should be the (function_declaration)
        let stmt_parent = ctx.get_ts_node_parent(stmt).unwrap();
        let stmt_parent = unsafe { stmt_parent.to_node() };
        assert_eq!(stmt_parent.kind(), "function_declaration");

        // The grandparent should be (program)
        let stmt_grandparent = ctx.get_ts_node_parent(stmt_parent).unwrap();
        let stmt_grandparent = unsafe { stmt_grandparent.to_node() };
        assert_eq!(stmt_grandparent.kind(), "program");
    }

    /// Getting the parent of the root node should return `None`.
    #[test]
    fn get_ts_node_parent_root() {
        let (ctx, tree) = setup_parent_test(PARENT_CODE);

        let root_node = tree.root_node();
        assert_eq!(ctx.get_ts_node_parent(root_node), None);
    }

    /// Getting the parent of a node from a different tree returns `None`.
    /// (NOTE: This is included for completeness -- there should never be a situation where this happens)
    #[test]
    fn get_ts_node_parent_wrong_tree() {
        let (ctx, _tree_1) = setup_parent_test(PARENT_CODE);

        let source_2: Arc<str> = Arc::from(PARENT_CODE_2);
        let tree_2 = Arc::new(get_tree(source_2.as_ref(), &Language::JavaScript).unwrap());

        let arrow = n_child(n_child(n_child(tree_2.root_node(), 0), 0), 1);
        assert_eq!(arrow.kind(), "arrow_function", "test invariant broken");

        assert_eq!(ctx.get_ts_node_parent(arrow), None);
    }

    /// Traversing to get a node's parent should only cache relationships along the root-to-node path.
    /// That is, if we were to imagine the traversal as a depth-first-search, we do not cache
    /// relationships that do not end up being a part of the direct path (those we had to backtrack on).
    /// (While this test seems redundant with `get_ts_node_parent`, we specifically use
    /// a more complicated test case with more and larger branches)
    #[test]
    fn get_ts_node_parent_only_cache_direct_path() {
        let code = "\
function echo() {
    const one = () => { /* comment_one */ };
    const two = () => { /* comment_two */ };
    const three = () => { /* comment_three */ };
}
";
        // Test invariant
        let expected = "\
(program (function_declaration name: (identifier) parameters: (formal_parameters) body: (statement_block \
    (lexical_declaration (variable_declarator name: (identifier) value: (arrow_function parameters: (formal_parameters) body: (statement_block (comment))))) \
    (lexical_declaration (variable_declarator name: (identifier) value: (arrow_function parameters: (formal_parameters) body: (statement_block (comment))))) \
    (lexical_declaration (variable_declarator name: (identifier) value: (arrow_function parameters: (formal_parameters) body: (statement_block (comment)))))\
)))";

        let (ctx, tree) = setup_parent_test(code);
        assert_eq!(tree.root_node().to_sexp(), expected, "invariant broken");

        let arrow_fn_with_idx = |index: usize| -> tree_sitter::Node {
            let lex_declarator = n_child(n_child(n_child(tree.root_node(), 0), 2), index);
            n_child(n_child(lex_declarator, 0), 1)
        };
        let comment_with_idx = |index: usize| -> tree_sitter::Node {
            n_child(n_child(arrow_fn_with_idx(index), 1), 0)
        };
        let text_for =
            |node: tree_sitter::Node| -> &str { node.utf8_text(code.as_bytes()).unwrap() };

        // Manually choose a (comment) node that _isn't_ the leftmost child of its parent.
        let comment_two = comment_with_idx(1);
        assert_eq!(text_for(comment_two), "/* comment_two */");

        assert_eq!(ctx.parent_map.borrow().len(), 0);
        assert!(ctx.get_ts_node_parent(comment_two).is_some());
        // There are 7 parent relationships in the root-to-node path:
        //          1.                    2.                3.                  4.                   5.              6.               7.
        // (program (function_declaration (statement_block (lexical_declaration (variable_declarator (arrow_function (statement_block (comment))))))))
        assert_eq!(ctx.parent_map.borrow().len(), 7);

        // Now, if we request a sibling to `comment_two`, we'll cache the additional relationships along that branch:
        //                                8.               9.                   10.
        // (program (function_declaration (statement_block (lexical_declaration (variable_declarator (arrow_function (statement_block (comment))))))))
        let arrow_fn_three = arrow_fn_with_idx(2);
        assert_eq!(text_for(arrow_fn_three), "() => { /* comment_three */ }");
        assert!(ctx.get_ts_node_parent(arrow_fn_three).is_some());
        assert_eq!(ctx.parent_map.borrow().len(), 10);

        // Now, if we traverse that path again (but deeper), we'll cache the rest of it:
        //                                                                                           11.             12.
        // (program (function_declaration (statement_block (lexical_declaration (variable_declarator (arrow_function (statement_block (comment))))))))
        let comment_three = comment_with_idx(2);
        assert_eq!(text_for(comment_three), "/* comment_three */");
        assert!(ctx.get_ts_node_parent(comment_three).is_some());
        assert_eq!(ctx.parent_map.borrow().len(), 12);
    }

    /// Traversing to get a node's parent should cache all parent relationships along the way.
    /// Parent cache should be performed lazily.
    #[test]
    fn get_ts_node_parent_root_lazy_cache() {
        let (ctx, tree) = setup_parent_test(PARENT_CODE);

        // The calculation should be lazy.
        assert!(ctx.tree.is_some());
        assert_eq!(ctx.parent_map.borrow().len(), 0);

        // Manually choose the (comment) node.
        let comment = n_child(n_child(n_child(tree.root_node(), 0), 2), 0);
        assert_eq!(comment.kind(), "comment");

        let comment_parent = ctx.get_ts_node_parent(comment).unwrap();
        // Note that we should've cached 3 parent relationships. We do not cache the fact `(program)` is the root.
        assert_eq!(ctx.parent_map.borrow().len(), 3);
        // We should've performed one traversal.
        assert_eq!(ctx._cfg_test_tree_traversal_count.get(), 1);

        // (program
        //     (function_declaration
        //         name: (identifier)
        //         parameters: (formal_parameters)
        //         body: (statement_block
        //                   (comment)              <- the node we call `get_ts_node_parent` on.
        //               )
        //     )
        // )
        // For ease of testing, as per the s-expression above, we know that each node `kind` only
        // appears once in the tree, so we can just use the `kind` to compare the equivalence of the hashmaps.
        let transformed_parent_map: HashMap<&str, &str> = ctx
            .parent_map
            .borrow()
            .iter()
            .map(|(&child_id, raw_parent)| {
                // NOTE: For the key, we only have a `child_id` (pointer to the `TSNode` C struct),
                // but we can't construct a `tree_sitter::Node` from that alone. Because this is a unit
                // test, we can afford to just iterate the parent's children and locate a matching id.
                let parent = unsafe { raw_parent.to_node() };
                let mut child: Option<tree_sitter::Node> = None;
                for idx in 0..parent.child_count() {
                    let node = parent.child(idx).unwrap();
                    if node.id() == child_id {
                        let _ = child.insert(node);
                        break;
                    }
                }
                let child = child.expect("raw_child_id should be child of raw_parent");
                (child.kind(), parent.kind())
            })
            .collect();

        let expected = HashMap::from([
            ("comment", "statement_block"),
            ("statement_block", "function_declaration"),
            ("function_declaration", "program"),
        ]);
        assert_eq!(transformed_parent_map, expected);

        // The cache contents were just verified. Now verify that subsequent calls use it.
        let comment_parent = unsafe { comment_parent.to_node() };
        let grandparent = ctx.get_ts_node_parent(comment_parent).unwrap();
        let grandparent = unsafe { grandparent.to_node() };
        assert_eq!(grandparent.kind(), "function_declaration");
        // We should've used the cache.
        assert_eq!(ctx._cfg_test_tree_traversal_count.get(), 1);
    }

    /// The parent relationship cache should be cleared when the [`RootContext`] tree is updated.
    #[test]
    fn get_ts_node_parent_cache_cleared() {
        let (mut ctx, tree_1) = setup_parent_test(PARENT_CODE);
        let tree_2 = Arc::new(get_tree(PARENT_CODE_2, &Language::JavaScript).unwrap());

        // Manually choose the (comment) node.
        let comment = n_child(n_child(n_child(tree_1.root_node(), 0), 2), 0);
        assert_eq!(comment.kind(), "comment");

        let _ = ctx.get_ts_node_parent(comment);
        assert_eq!(ctx.parent_map.borrow().len(), 3);

        ctx.set_tree(tree_2);
        assert_eq!(ctx.parent_map.borrow().len(), 0);
    }
}
