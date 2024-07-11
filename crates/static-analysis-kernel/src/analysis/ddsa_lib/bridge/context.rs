// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib;
use crate::analysis::ddsa_lib::common::{DDSAJsRuntimeError, Instance};
use crate::analysis::ddsa_lib::js;
use crate::model::common::Language;
use deno_core::v8;
use deno_core::v8::HandleScope;
use std::ops::Deref;
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
    ts_lang: Linked<ddsa_lib::TsLanguageContext, js::TsLanguageContext<Instance>>,
}

impl ContextBridge {
    /// Constructs a new `ContextBridge` for the given `scope`. The scope's [`v8::Context::global`] must
    /// have class functions with the following identifiers:
    /// * [`js::RootContext::CLASS_NAME`]
    /// * [`js::RuleContext::CLASS_NAME`]
    /// * [`js::FileContext::CLASS_NAME`]
    /// * [`js::TsLanguageContext::CLASS_NAME`]
    ///
    ///
    /// Note that individual [`ddsa_lib::FileContext`] instances may require their own class functions
    /// to be present in the scope, and these contexts can be viewed at [`Self::init_all_file_ctx`].
    pub fn try_new(scope: &mut HandleScope) -> Result<Self, DDSAJsRuntimeError> {
        let js_root_ctx = js::RootContext::try_new(scope)?;
        let js_rule_ctx = js::RuleContext::try_new(scope)?;
        let js_file_ctx = js::FileContext::try_new(scope)?;
        let js_ts_lang_ctx = js::TsLanguageContext::try_new(scope)?;

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
        let ts_lang = Linked {
            ddsa: ddsa_lib::TsLanguageContext::default(),
            js: js_ts_lang_ctx,
        };
        // Initialize the contexts
        rule.js
            .set_arguments_map(scope, Some(rule.ddsa.arguments_map()));
        Self::init_all_file_ctx(scope, &mut file)?;
        // Attach the `ruleCtx` and `fileCtx` to the root context.
        root.js.set_rule_ctx(scope, Some(&rule.js));
        root.js.set_file_ctx(scope, Some(&file.js));
        root.js.set_ts_lang_ctx(scope, Some(&ts_lang.js));

        Ok(Self {
            root,
            rule,
            file,
            ts_lang,
        })
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
        let mut was_new_ts_lang = false;
        // NOTE:
        // We know that two trees are equal if their root node is the same because
        // we never mutate trees (or nodes).
        if self.root.ddsa.get_tree().map(|ex| ex.root_node().id()) != Some(tree.root_node().id()) {
            was_new_tree = true;
            let previous_tree = self.root.ddsa.set_tree(Arc::clone(tree));
            if previous_tree.is_none() {
                was_new_ts_lang = true
            } else if let Some(prev_tree) = previous_tree {
                was_new_ts_lang = prev_tree.language().deref() != tree.language().deref();
            }
        }
        // If the existing language was different from the one for this tree, update the context.
        if was_new_ts_lang {
            let metadata = self
                .ts_lang
                .ddsa
                .get_metadata(scope, tree.language().deref());
            self.ts_lang.js.set_metadata(
                scope,
                Some(metadata.node_kind_map.v8_map()),
                Some(metadata.field_map.v8_map()),
            );
            // For now, in the interest of simplicity, we just clear all file contexts when the
            // language changes (as opposed to only clearing the context for the preceding language).
            // This really has no performance impact, as the number of times we'll change languages
            // has an upper bound of the count of [`crate::model::common::Language`] variants.
            self.clear_file_contexts(scope);
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

    /// Updates the file context for the specific `Language`.
    ///
    /// NOTE: It's up to the caller to ensure [`Self::clear_file_contexts`] has been called,
    /// as this function does not clear existing contexts.
    pub fn set_file_context(
        &mut self,
        scope: &mut HandleScope,
        language: Language,
        tree: &tree_sitter::Tree,
        file_contents: &Arc<str>,
    ) {
        match language {
            Language::Go => {
                if let Some(go) = self.file.ddsa.go_mut() {
                    go.update_state(scope, tree, file_contents.as_ref());
                }
            }
            Language::Terraform => {
                if let Some(tf) = self.file.ddsa.tf_mut() {
                    tf.update_state(scope, tree, file_contents.as_ref());
                }
            }
            Language::JavaScript => {
                if let Some(js) = self.file.ddsa.js_mut() {
                    js.update_state(tree, file_contents.clone());
                }
            }
            _ => {}
        }
    }

    /// Clears all file contexts
    fn clear_file_contexts(&mut self, scope: &mut HandleScope) {
        if let Some(go) = self.file.ddsa.go_mut() {
            go.clear(scope);
        }
        if let Some(tf) = self.file.ddsa.tf_mut() {
            tf.clear(scope);
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
        let ddsa_js = ddsa_lib::FileContextJavaScript::new();
        let ddsa_tf = ddsa_lib::FileContextTerraform::new(scope)?;
        let js_go = js::FileContextGo::try_new(scope)?;
        let js_js = js::FileContextJavaScript::try_new(scope)?;
        let js_tf = js::FileContextTerraform::try_new(scope)?;
        js_go.set_pkg_alias_map(scope, Some(ddsa_go.package_alias_v8_map()));
        js_tf.set_module_resource_array(scope, Some(ddsa_tf.resources_v8_array()));
        file.js.initialize_go(scope, js_go);
        file.js.initialize_tf(scope, js_tf);
        file.js.initialize_js(scope, js_js);
        file.ddsa.set_go(ddsa_go);
        file.ddsa.set_js(ddsa_js);
        file.ddsa.set_tf(ddsa_tf);
        Ok(())
    }

    /// Provides a reference to the [`ddsa_lib::FileContext`] for inspection in tests.
    #[cfg(test)]
    pub fn ddsa_file_ctx(&self) -> &ddsa_lib::FileContext {
        &self.file.ddsa
    }

    /// Provides a mutable reference to the [`ddsa_lib::FileContext`]
    pub fn ddsa_file_ctx_mut(&mut self) -> &mut ddsa_lib::FileContext {
        &mut self.file.ddsa
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::bridge::ContextBridge;
    use crate::analysis::ddsa_lib::common::v8_string;
    use crate::analysis::ddsa_lib::test_utils::{
        attach_as_global, cfg_test_runtime, format_ts_lang_pointer, parse_code, try_execute,
        KEY_TS_LANGUAGE_PTR,
    };
    use crate::analysis::tree_sitter::get_tree;
    use crate::model::common::Language;
    use deno_core::v8;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::ops::Deref;
    use std::rc::Rc;
    use std::sync::Arc;

    /// A function that performs an `assert!` that the [`js::TsLanguageContext`](crate::analysis::ddsa_lib::js::TsLanguageContext)
    /// on the bridge contains metadata for the expected `tree_sitter::Language`.
    fn assert_ts_lang_ctx(
        scope: &mut v8::HandleScope,
        bridge: &ContextBridge,
        expected: &tree_sitter::Language,
    ) {
        let s_lang_ptr = v8_string(scope, KEY_TS_LANGUAGE_PTR);
        let lang_address = format_ts_lang_pointer(expected);

        let field_map = bridge.ts_lang.js.get_prop_field(scope);
        let node_type_map = bridge.ts_lang.js.get_prop_node_type(scope);

        for v8_map in [field_map, node_type_map] {
            let entry_value = v8_map.get(scope, s_lang_ptr.into()).unwrap();
            assert_eq!(entry_value.to_rust_string_lossy(scope), lang_address);
            // Assert that this map has been populated: we check that it's over 1 because
            // we artificially inserted the `s_lang_ptr` entry.
            assert!(v8_map.size() > 1);
        }
    }

    /// Ensures that the file content and filename cache is cleared every time they are set.
    #[rustfmt::skip]
    #[test]
    fn set_root_context_clears_cache() {
        let mut runtime = cfg_test_runtime();
        let scope = &mut runtime.handle_scope();
        let contents_1: Arc<str> = Arc::from("const fileContents = '11111'");
        let filename_1: Arc<str> = Arc::from("11111.js");
        let tree_1 = Arc::new(parse_code(contents_1.as_ref(), Language::JavaScript));
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
        let tree_2 = Arc::new(parse_code(contents_2.as_ref(), Language::JavaScript));
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

    /// Tests that the tree-sitter language context is updated when the `RootContext` is set.
    #[test]
    fn set_root_context_ts_lang() {
        let mut runtime = cfg_test_runtime();
        let scope = &mut runtime.handle_scope();
        let mut bridge = ContextBridge::try_new(scope).unwrap();

        // First assert that the TsLanguageContext is uninitialized
        assert_eq!(bridge.ts_lang.js.get_prop_node_type(scope).size(), 0);
        assert_eq!(bridge.ts_lang.js.get_prop_field(scope).size(), 0);

        // Then set the RootContext for a JavaScript tree.
        let contents_1: Arc<str> = Arc::from("const fileContents = '11111'");
        let filename_1: Arc<str> = Arc::from("11111.js");
        let tree_1 = Arc::new(parse_code(contents_1.as_ref(), Language::JavaScript));
        bridge.set_root_context(scope, &tree_1, &contents_1, &filename_1);
        // Assert that it gets initialized for the JavaScript tree-sitter language.
        assert_ts_lang_ctx(scope, &bridge, tree_1.language().deref());

        // Then set the RootContext for a non-JavaScript tree.
        let contents_2: Arc<str> = Arc::from("fileContents = '22222'");
        let filename_2: Arc<str> = Arc::from("22222.py");
        let tree_2 = Arc::new(parse_code(contents_2.as_ref(), Language::Python));
        assert_ne!(tree_1.language().deref(), tree_2.language().deref());
        bridge.set_root_context(scope, &tree_2, &contents_2, &filename_2);
        // Assert that it gets reassigned to the Python tree-sitter language.
        assert_ts_lang_ctx(scope, &bridge, tree_2.language().deref());
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

    #[rustfmt::skip]
    #[test]
    /// Tests that terraform resources are eagerly calculated by calling `set_file_context`.
    fn test_fetch_terraform_resources_eagerly() {
        let mut runtime = cfg_test_runtime();
        let bridge = ContextBridge::try_new(&mut runtime.handle_scope()).unwrap();
        attach_as_global(
            &mut runtime.handle_scope(),
            bridge.file.js.v8_object(),
            "FILE_CTX_BRIDGE",
        );
        let bridge = Rc::new(RefCell::new(bridge));
        runtime.op_state().borrow_mut().put(Rc::clone(&bridge));
        let scope = &mut runtime.handle_scope();

        let filename = Arc::<str>::from("filename.tf");
        let file_contents = r#"
resource "aws_instance" "web" {
    ami           = "ami-1234567890"
    instance_type = "t2.micro"
}

resource "google_compute_instance" "db" {
    project      = "my-project"
    name         = "db"
    machine_type = "n1-standard-1"
}"#;

        let tree = Arc::new(get_tree(file_contents, &Language::Terraform).unwrap());
        let file_contents = Arc::<str>::from(file_contents);
        let mut mut_bridge = bridge.borrow_mut();
        assert_eq!(mut_bridge.file.ddsa.tf().unwrap().resources_v8_array().open(scope).length(), 0);
        mut_bridge.set_root_context(scope, &tree, &file_contents, &filename);
        assert_eq!(mut_bridge.file.ddsa.tf().unwrap().resources_v8_array().open(scope).length(), 0);
        mut_bridge.set_file_context(scope, Language::Terraform, &tree, &file_contents);
        assert_eq!(mut_bridge.file.ddsa.tf().unwrap().resources_v8_array().open(scope).length(), 2);
        let code = r#"
FILE_CTX_BRIDGE.terraform.resources.map(r => `${r.type}:${r.name}`).join(',');
"#;
        drop(mut_bridge);
        let result = try_execute(scope, code).unwrap();
        assert_eq!(
            result.to_rust_string_lossy(scope),
            "aws_instance:web,google_compute_instance:db"
        );
    }

    #[rustfmt::skip]
    #[test]
    /// Tests that JavaScript package imports are eagerly calculated by calling `set_file_context`.
    fn test_fetch_js_package_imports_eagerly() {
        let mut runtime = cfg_test_runtime();
        let bridge = ContextBridge::try_new(&mut runtime.handle_scope()).unwrap();
        attach_as_global(
            &mut runtime.handle_scope(),
            bridge.file.js.v8_object(),
            "FILE_CTX_BRIDGE",
        );
        let bridge = Rc::new(RefCell::new(bridge));
        runtime.op_state().borrow_mut().put(Rc::clone(&bridge));
        let scope = &mut runtime.handle_scope();

        let filename = Arc::<str>::from("filename.js");
        let file_contents = r#"
            import { foo } from 'bar';
            import * as baz from 'qux';
        "#;

        let tree = Arc::new(get_tree(file_contents, &Language::JavaScript).unwrap());
        let file_contents = Arc::<str>::from(file_contents);
        let mut mut_bridge = bridge.borrow_mut();
        mut_bridge.set_root_context(scope, &tree, &file_contents, &filename);
        mut_bridge.set_file_context(scope, Language::JavaScript, &tree, &file_contents);

        drop(mut_bridge);
        let code = "FILE_CTX_BRIDGE.jsImportsPackage('bar')";
        let result = try_execute(scope, code).unwrap();
        assert_eq!(result.boolean_value(scope), true);

        let code = "FILE_CTX_BRIDGE.jsImportsPackage('not_an_import')";
        let result = try_execute(scope, code).unwrap();
        assert_eq!(result.boolean_value(scope), false);
    }
}
