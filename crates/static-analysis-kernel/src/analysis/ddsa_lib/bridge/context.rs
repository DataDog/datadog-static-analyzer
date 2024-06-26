// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib;
use crate::analysis::ddsa_lib::common::{DDSAJsRuntimeError, Instance};
use crate::analysis::ddsa_lib::js;
use crate::model::common::Language;
use deno_core::v8;
use deno_core::v8::HandleScope;
use std::sync::Arc;

/// A [`ddsa_lib`] Context and its corresponding [`js`] Context.
#[derive(Debug)]
struct Linked<T, U> {
    pub ddsa: T,
    pub js: U,
}

/// A stateful bridge used to update all [`ddsa_lib::context`]s.
#[derive(Debug)]
pub struct ContextBridge {
    root: Linked<ddsa_lib::RootContext, js::RootContext<Instance>>,
    rule: Linked<ddsa_lib::RuleContext, js::RuleContext<Instance>>,
    file: Linked<ddsa_lib::FileContext, js::FileContext<Instance>>,
}

impl ContextBridge {
    /// Constructs a new `ContextBridge` for the given `scope`. The scope's [`v8::Context::global`] must
    /// have class functions with the following identifiers:
    /// * [`js::RootContext::CLASS_NAME`]
    /// * [`js::RuleContext::CLASS_NAME`]
    /// * [`js::FileContext::CLASS_NAME`]
    ///
    /// Note that individual [`ddsa_lib::FileContext`] instances may require their own class functions
    /// to be present in the scope, and these contexts can be viewed at [`Self::init_all_file_ctx`].
    pub fn try_new(scope: &mut HandleScope) -> Result<Self, DDSAJsRuntimeError> {
        let js_root_ctx = js::RootContext::try_new(scope)?;
        let js_rule_ctx = js::RuleContext::try_new(scope)?;
        let js_file_ctx = js::FileContext::try_new(scope)?;

        let root = Linked {
            ddsa: ddsa_lib::RootContext::default(),
            js: js_root_ctx,
        };
        let rule = Linked {
            ddsa: ddsa_lib::RuleContext::new(scope),
            js: js_rule_ctx,
        };
        let mut file = Linked {
            ddsa: ddsa_lib::FileContext::default(),
            js: js_file_ctx,
        };
        // Initialize the contexts
        rule.js
            .set_arguments_map(scope, Some(rule.ddsa.arguments_map()));
        Self::init_all_file_ctx(scope, &mut file)?;
        // Attach the `ruleCtx` and `fileCtx` to the root context.
        root.js.set_rule_ctx(scope, Some(&rule.js));
        root.js.set_file_ctx(scope, Some(&file.js));

        Ok(Self { root, rule, file })
    }

    /// Returns a local handle to the underlying [`v8::Global`] object.
    pub fn as_local<'s>(&self, scope: &mut HandleScope<'s>) -> v8::Local<'s, v8::Object> {
        self.root.js.as_local(scope)
    }

    /// Assigns the provided metadata to the context.
    ///
    /// Returns `true` if the incoming `tree` was different from the last one analyzed, or `false`
    /// if they were the same.
    pub fn set_root_context(
        &mut self,
        scope: &mut HandleScope,
        tree: &Arc<tree_sitter::Tree>,
        file_contents: &Arc<str>,
        filename: &Arc<str>,
    ) -> bool {
        let mut was_new_tree = false;
        // NOTE:
        // We know that two trees are equal if their root node is the same because
        // we never mutate trees (or nodes).
        if self.root.ddsa.get_tree().map(|ex| ex.root_node().id()) != Some(tree.root_node().id()) {
            self.root.ddsa.set_tree(Arc::clone(tree));
            was_new_tree = true;
        }
        // Because trees and file contents go hand-in-hand, we can avoid a relatively expensive string
        // comparison by just using the `new_tree` boolean for control flow.
        if was_new_tree {
            self.root.ddsa.set_text(Arc::clone(file_contents));
            // The cache is populated lazily, so a change in value means we need to clear the cache.
            self.root.js.set_file_contents_cache(scope, None);
        }
        if self.root.ddsa.get_filename() != Some(filename.as_ref()) {
            self.root.ddsa.set_filename(Arc::clone(filename));
            // The cache is populated lazily, so a change in value means we need to clear the cache.
            self.root.js.set_filename_cache(scope, None);
        }
        was_new_tree
    }

    /// Assigns the provide rule arguments to the context.
    pub fn set_rule_arguments<K: Into<String>, V: Into<String>>(
        &mut self,
        scope: &mut HandleScope,
        args: impl IntoIterator<Item = (K, V)>,
    ) {
        self.rule.ddsa.clear_arguments(scope);
        for (arg_name, arg_value) in args {
            self.rule.ddsa.insert_argument(scope, arg_name, arg_value)
        }
    }

    /// Updates the file contexts that have been initialized, given the file.
    pub fn set_file_context(
        &mut self,
        scope: &mut HandleScope,
        language: Language,
        tree: &tree_sitter::Tree,
        file_contents: &Arc<str>,
    ) {
        // Because we allocate all Mirrored v8 data structures ahead of time, the role of this function
        // is to clear out the ones that no longer apply.
        // A file can only have a single file context.
        if language == Language::Go {
            if let Some(go) = self.file.ddsa.go_mut() {
                go.update_state(scope, tree, file_contents.as_ref());
            }
        } else if let Some(go) = self.file.ddsa.go_mut() {
            go.clear(scope);
        }
    }

    /// Returns a reference to the underlying `ddsa_lib::RootContext`.
    pub(crate) fn ddsa_root_context(&self) -> &ddsa_lib::RootContext {
        &self.root.ddsa
    }

    /// Initializes all file contexts supported by the associated [`ddsa_lib::FileContext`].
    fn init_all_file_ctx(
        scope: &mut HandleScope,
        file: &mut Linked<ddsa_lib::FileContext, js::FileContext<Instance>>,
    ) -> Result<(), DDSAJsRuntimeError> {
        let ddsa_go = ddsa_lib::FileContextGo::new(scope);
        let js_go = js::FileContextGo::try_new(scope)?;
        js_go.set_pkg_alias_map(scope, Some(ddsa_go.package_alias_v8_map()));
        file.js.initialize_go(scope, js_go);
        file.ddsa.set_go(ddsa_go);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::bridge::ContextBridge;
    use crate::analysis::ddsa_lib::common::v8_string;
    use crate::analysis::ddsa_lib::test_utils::{
        attach_as_global, cfg_test_runtime, parse_js, try_execute,
    };
    use crate::analysis::tree_sitter::get_tree;
    use crate::model::common::Language;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;
    use std::sync::Arc;

    /// Ensures that the file content and filename cache is cleared every time they are set.
    #[rustfmt::skip]
    #[test]
    fn set_root_context_clears_cache() {
        let mut runtime = cfg_test_runtime();
        let scope = &mut runtime.handle_scope();
        let contents_1: Arc<str> = Arc::from("const fileContents = '11111'");
        let filename_1: Arc<str> = Arc::from("11111.js");
        let tree_1 = Arc::new(parse_js(contents_1.as_ref()));
        let mut bridge = ContextBridge::try_new(scope).unwrap();
        assert!(bridge.root.js.get_file_contents_cache(scope).is_none());
        assert!(bridge.root.js.get_filename_cache(scope).is_none());
        bridge.set_root_context(scope, &tree_1, &contents_1, &filename_1);
        assert!(bridge.root.js.get_file_contents_cache(scope).is_none());
        assert!(bridge.root.js.get_filename_cache(scope).is_none());
        // Set the caches to simulate them being warmed
        bridge.root.js.set_file_contents_cache(scope, Some(contents_1.as_ref()));
        bridge.root.js.set_filename_cache(scope, Some(filename_1.as_ref()));

        assert_eq!(bridge.root.js.get_file_contents_cache(scope).unwrap(), contents_1.to_string());
        assert_eq!(bridge.root.js.get_filename_cache(scope).unwrap(), filename_1.to_string());
        let contents_2: Arc<str> = Arc::from("const fileContents = '22222'");
        let filename_2: Arc<str> = Arc::from("22222.js");
        let tree_2 = Arc::new(parse_js(contents_2.as_ref()));
        bridge.set_root_context(scope, &tree_2, &contents_2, &filename_2);
        assert!(bridge.root.js.get_file_contents_cache(scope).is_none());
        assert!(bridge.root.js.get_filename_cache(scope).is_none());
    }

    /// Ensures `set_rule_arguments` updates the JavaScript map, and that sequential calls don't co-mingle arguments.
    #[rustfmt::skip]
    #[test]
    fn set_rule_context_args_is_exact() {
        let mut runtime = cfg_test_runtime();
        let scope = &mut runtime.handle_scope();
        let mut bridge = ContextBridge::try_new(scope).unwrap();
        assert!(bridge.rule.js.v8_arguments_map(scope).is_some());
        let v8_args_map = bridge.rule.js.v8_arguments_map(scope).unwrap();

        let args = HashMap::from([("max_lines", "200"), ("target", "def")]);
        bridge.set_rule_arguments(scope, args.iter().map(|(&k, &v)| (k, v)));
        for (&key, &value) in &args {
            let v8_key = v8_string(scope, key);
            assert_eq!(v8_args_map.get(scope, v8_key.into()).unwrap().to_rust_string_lossy(scope).as_str(), value);
        }

        let old_args = args;
        let new_args = HashMap::from([("disallowed_words", "foo,bar")]);
        bridge.set_rule_arguments(scope, new_args.iter().map(|(&k, &v)| (k, v)));
        for &key in old_args.keys() {
            let v8_key = v8_string(scope, key);
            assert!(v8_args_map.get(scope, v8_key.into()).unwrap().is_undefined());
        }
        for (&key, &value) in &new_args {
            let v8_key = v8_string(scope, key);
            assert_eq!(v8_args_map.get(scope, v8_key.into()).unwrap().to_rust_string_lossy(scope), value);
        }
    }

    #[rustfmt::skip]
    #[test]
    /// Tests that go module aliases are eagerly calculated by calling `set_file_context`.
    fn test_fetch_go_module_alias_eagerly() {
        let mut runtime = cfg_test_runtime();
        let bridge = ContextBridge::try_new(&mut runtime.handle_scope()).unwrap();
        attach_as_global(&mut runtime.handle_scope(), bridge.file.js.v8_object(), "FILE_CTX_BRIDGE");
        let bridge = Rc::new(RefCell::new(bridge));
        runtime.op_state().borrow_mut().put(Rc::clone(&bridge));
        let scope = &mut runtime.handle_scope();

        let filename = Arc::<str>::from("filename.go");
        let file_contents = r#"
import (
    "fmt"
    mrand "math/rand"
)
"#;
        let tree = Arc::new(get_tree(file_contents, &Language::Go).unwrap());
        let file_contents = Arc::<str>::from(file_contents);
        let mut mut_bridge = bridge.borrow_mut();
        assert_eq!(mut_bridge.file.ddsa.go().unwrap().package_alias_v8_map().open(scope).size(), 0);
        mut_bridge.set_root_context(scope, &tree, &file_contents, &filename);
        assert_eq!(mut_bridge.file.ddsa.go().unwrap().package_alias_v8_map().open(scope).size(), 0);
        mut_bridge.set_file_context(scope, Language::Go, &tree, &file_contents);
        assert_eq!(mut_bridge.file.ddsa.go().unwrap().package_alias_v8_map().open(scope).size(), 2);
        let code = r#"
FILE_CTX_BRIDGE.go.getResolvedPackage("mrand");
"#;
        drop(mut_bridge);
        let result = try_execute(scope, code).unwrap();
        assert_eq!(result.to_rust_string_lossy(scope), "math/rand");

        // The JavaScript code does not mutate the map.
        let bridge = bridge.borrow_mut();
        assert_eq!(bridge.file.ddsa.go().unwrap().package_alias_v8_map().open(scope).size(), 2);
    }
}
