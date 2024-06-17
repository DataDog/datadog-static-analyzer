// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::{v8_interned, v8_uint};
use crate::analysis::ddsa_lib::v8_ds::MirroredIndexMap;
use deno_core::v8;
use deno_core::v8::HandleScope;
use std::cell::RefCell;
use std::collections::HashMap;

/// A stateful bridge holding a collection of [`MirroredTsSymbolMap`].
#[derive(Default)]
pub struct TsSymbolMapBridge(RefCell<HashMap<tree_sitter::Language, MirroredTsSymbolMap>>);

impl TsSymbolMapBridge {
    /// Creates a new, empty `TsSymbolMapBridge`.
    pub fn new() -> Self {
        Self::with_capacity(0)
    }

    /// Creates a new, empty `TsSymbolMapBridge` with at least the specified capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self(RefCell::new(HashMap::with_capacity(capacity)))
    }

    /// Returns a local handle to the underlying [`v8::Global`] map for a specific language.
    pub fn get_map<'s>(
        &self,
        scope: &mut HandleScope<'s>,
        language: &tree_sitter::Language,
    ) -> v8::Local<'s, v8::Map> {
        if let Some(global_map) = self.0.borrow().get(language) {
            return global_map.as_local(scope);
        }
        let mut map = self.0.borrow_mut();
        let global_map = map
            .entry(language.clone())
            .or_insert_with(|| MirroredTsSymbolMap::new(scope, language));

        global_map.as_local(scope)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
enum NameOrSymbol {
    Name(&'static str),
    Symbol(u16),
}

/// A mapping and reverse mapping between a tree-sitter node's string name and its [`TSSymbol`](tree_sitter::ffi::TSSymbol).
///
/// Only "visible" and "named" nodes are included in this map.
#[derive(Debug)]
struct MirroredTsSymbolMap(MirroredIndexMap<NameOrSymbol, NameOrSymbol>);

impl MirroredTsSymbolMap {
    pub fn new(scope: &mut HandleScope, ts_language: &tree_sitter::Language) -> Self {
        let mut map = MirroredIndexMap::<NameOrSymbol, NameOrSymbol>::new(scope);
        (0..ts_language.node_kind_count() as u16)
            .filter(|&id| {
                ts_language.node_kind_is_visible(id) && ts_language.node_kind_is_named(id)
            })
            .for_each(|id| {
                use NameOrSymbol::{Name, Symbol};

                let symbol_name = ts_language.node_kind_for_id(id).expect("id should exist");
                let v8_symbol_name = v8_interned(scope, symbol_name);
                let v8_id = v8_uint(scope, id as u32);
                // Mapping: name -> symbol
                map.insert_with(scope, Name(symbol_name), Symbol(id), |_, _, _| {
                    (v8_symbol_name.into(), v8_id.into())
                });
                // Reverse mapping: symbol -> name
                map.insert_with(scope, Symbol(id), Name(symbol_name), |_, _, _| {
                    (v8_id.into(), v8_symbol_name.into())
                });
            });
        Self(map)
    }

    /// Returns a local handle to the underlying [`v8::Global`] map.
    pub fn as_local<'s>(&self, scope: &mut HandleScope<'s>) -> v8::Local<'s, v8::Map> {
        self.0.as_local(scope)
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::bridge::ts_symbol_map::TsSymbolMapBridge;
    use crate::analysis::ddsa_lib::common::v8_interned;
    use crate::analysis::ddsa_lib::test_utils::{attach_as_global, cfg_test_runtime, try_execute};
    use crate::analysis::tree_sitter::get_tree_sitter_language;
    use crate::model::common::Language;
    use deno_core::v8;
    use std::collections::HashSet;
    use std::num::NonZeroI32;

    /// The TSSymbol map builds maps for each language lazily.
    #[test]
    fn ts_symbol_map_lazy() {
        let mut runtime = cfg_test_runtime();
        let tsm_bridge = TsSymbolMapBridge::new();
        assert!(tsm_bridge.0.borrow().is_empty());
        let lang_js = get_tree_sitter_language(&Language::JavaScript);
        let lang_py = get_tree_sitter_language(&Language::Python);
        let scope = &mut runtime.handle_scope();
        let global = scope.get_current_context().global(scope);
        let s_lookup = v8_interned(scope, "SYMBOL_MAP");
        assert!(global.get(scope, s_lookup.into()).unwrap().is_undefined());
        let code = r#"
SYMBOL_MAP.get("identifier");
"#;
        let res = try_execute(scope, code).unwrap_err();
        assert_eq!(&res, "ReferenceError: SYMBOL_MAP is not defined");

        for (idx, lang) in [lang_js, lang_py].iter().enumerate() {
            assert_eq!(tsm_bridge.0.borrow().len(), idx);
            let lang_map = tsm_bridge.get_map(scope, lang);
            // It was just lazily-instantiated.
            assert_eq!(tsm_bridge.0.borrow().len(), idx + 1);
            global.set(scope, s_lookup.into(), lang_map.into());

            let res = try_execute(scope, code);
            let returned = res.unwrap().integer_value(scope).unwrap() as u16;
            assert_eq!(lang.node_kind_for_id(returned).unwrap(), "identifier");
        }
    }

    /// The v8 map should contain both a mapping from string -> TSSymbol, and TSSymbol -> string.
    #[test]
    fn ts_symbol_map_and_reverse_map() {
        let mut runtime = cfg_test_runtime();
        let tsm_bridge = TsSymbolMapBridge::new();
        let lang_js = get_tree_sitter_language(&Language::JavaScript);
        let scope = &mut runtime.handle_scope();
        let lang_map = tsm_bridge.get_map(scope, &lang_js);
        attach_as_global(scope, lang_map, "SYMBOL_MAP");
        let code = r#"
SYMBOL_MAP.get("identifier");
"#;
        let res = try_execute(scope, code).unwrap();
        let ret_symbol = res.integer_value(scope).unwrap();
        assert_eq!(ret_symbol, 49);
        let code = r#"
SYMBOL_MAP.get(49);
"#;
        let res = try_execute(scope, code).unwrap();
        let ret_name = res.to_rust_string_lossy(scope);
        assert_eq!(ret_name, "identifier");
    }

    /// The map only allocates a single [`v8::Map`] per language, regardless of how many contexts
    /// it is inserted into.
    #[test]
    fn ts_symbol_map_single_alloc() {
        let mut runtime = cfg_test_runtime();
        let tsm_bridge = TsSymbolMapBridge::new();
        let lang_ts = get_tree_sitter_language(&Language::TypeScript);
        let lang_js = get_tree_sitter_language(&Language::JavaScript);
        let lang_py = get_tree_sitter_language(&Language::Python);
        let scope = &mut runtime.handle_scope();

        // The v8 identity hash, although not stable between isolates, is stable within an isolate.
        let mut id_hashes = HashSet::<NonZeroI32>::new();
        let langs = &[lang_ts, lang_js, lang_py];
        for lang in std::iter::repeat(langs).flat_map(|l| l.iter()).take(10) {
            let ctx = v8::Context::new(scope);
            let scope = &mut v8::ContextScope::new(scope, ctx);
            let v8_map = tsm_bridge.get_map(scope, lang);
            attach_as_global(scope, v8_map, "SYMBOL_MAP");
            let code = r#"
SYMBOL_MAP.get("identifier");
"#;
            let res = try_execute(scope, code);
            assert!(res.unwrap().is_int32());
            id_hashes.insert(v8_map.get_identity_hash());
        }
        assert_eq!(id_hashes.len(), langs.len());
    }
}
