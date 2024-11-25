// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::{v8_interned, v8_uint};
use crate::analysis::ddsa_lib::v8_ds::MirroredIndexMap;
use deno_core::v8::HandleScope;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct TsLanguageContext {
    /// A lazily-instantiated cache for per-language `Metadata`.
    metadata: HashMap<tree_sitter::Language, Metadata>,
}

impl TsLanguageContext {
    /// Gets a reference to [`Metadata`] for the provided `tree_sitter::Language`.
    pub(crate) fn get_metadata(
        &mut self,
        scope: &mut HandleScope,
        language: &tree_sitter::Language,
    ) -> &Metadata {
        self.metadata
            // `language` is cheap to clone (it's implemented as a reference-counting pointer),
            // but additionally, we don't expect `get_metadata` to be called often.
            .entry(language.clone())
            .or_insert_with(|| Metadata::new(scope, language))
    }
}

/// Metadata for a [`tree_sitter::Language`], stored as two `v8::Global` Maps.
#[derive(Debug)]
pub(crate) struct Metadata {
    /// A mapping and reverse mapping between a tree-sitter node's kind id and the string name for that id.
    ///
    /// Only "visible" and "named" nodes are included in this map.
    pub(crate) node_kind_map: MirroredIndexMap<NameOrId, NameOrId>,
    /// A mapping and reverse mapping between a tree-sitter node field id and the string name for that id.
    pub(crate) field_map: MirroredIndexMap<NameOrId, NameOrId>,
}

impl Metadata {
    /// Extracts metadata from the provided `ts_language`.
    pub fn new(scope: &mut HandleScope, ts_language: &tree_sitter::Language) -> Self {
        // NOTE: We debug_assert that node kind ids are 0-based.
        let is_zero_based_id = true;
        debug_assert!(ts_language.node_kind_for_id(0).is_some());
        debug_assert!(ts_language
            .node_kind_for_id(ts_language.node_kind_count() as u16)
            .is_none());
        debug_assert!(is_zero_based_id);
        let node_kind_map = new_metadata_map(
            scope,
            ts_language,
            |ts_lang| ts_lang.node_kind_count(),
            is_zero_based_id,
            |ts_lang, id| ts_lang.node_kind_is_visible(id) && ts_lang.node_kind_is_named(id),
            |ts_lang, id| ts_lang.node_kind_for_id(id).expect("id should exist"),
        );

        // NOTE: We debug_assert that field ids are 1-based.
        let is_zero_based_id = false;
        debug_assert!(ts_language.field_name_for_id(0).is_none());
        debug_assert!(ts_language
            .field_name_for_id(ts_language.field_count() as u16)
            .is_some());
        debug_assert!(!is_zero_based_id);
        let field_map = new_metadata_map(
            scope,
            ts_language,
            |ts_lang| ts_lang.field_count(),
            is_zero_based_id,
            |_, _| true,
            |ts_lang, id| ts_lang.field_name_for_id(id).expect("id should exist"),
        );
        Self {
            node_kind_map,
            field_map,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum NameOrId {
    Name(&'static str),
    Id(u16),
}

/// Constructs a new [`MirroredIndexMap`] that contains a mapping and a reverse mapping between a facet
/// of metadata for a [`tree_sitter::Language`]. For example, this could represent a map between
/// [`Node::kind`](tree_sitter::Node::kind) and [`Node::kind_id`](tree_sitter::Node::kind_id).
///
/// # Parameters
/// * `count`:         A closure that returns the number of ids to iterate.
/// * `zero_based_id`: `true` if the id for this metadata is 0-based, `false` if the id is 1-based.
/// * `filter`:        A closure that determines whether a specific id should be included in the map.
/// * `name_for_id`:   A closure that generates a string name from an id.
///
/// Note: For unit tests, the `v8::Map` will contain an additional entry, with the key being
/// [`test_utils::KEY_TS_LANGUAGE_PTR`](crate::analysis::ddsa_lib::test_utils::KEY_TS_LANGUAGE_PTR),
/// and the value being the output of the `ts_language` passed to
/// [`test_utils::format_ts_lang_pointer`](crate::analysis::ddsa_lib::test_utils::format_ts_lang_pointer).
pub(crate) fn new_metadata_map<T, U, V>(
    scope: &mut HandleScope,
    ts_language: &tree_sitter::Language,
    count: T,
    zero_based_id: bool,
    filter: U,
    name_for_id: V,
) -> MirroredIndexMap<NameOrId, NameOrId>
where
    T: Fn(&tree_sitter::Language) -> usize,
    U: Fn(&tree_sitter::Language, u16) -> bool,
    V: Fn(&tree_sitter::Language, u16) -> &'static str,
{
    let mut imap = MirroredIndexMap::<NameOrId, NameOrId>::new(scope);
    (0..count(ts_language))
        .map(|idx| if zero_based_id { idx } else { idx + 1 } as u16)
        .filter(|&id| filter(ts_language, id))
        .for_each(|id| {
            use NameOrId::{Id, Name};

            let name = name_for_id(ts_language, id);
            let v8_name = v8_interned(scope, name);
            let v8_id = v8_uint(scope, id as u32);
            // Mapping: name -> id
            imap.insert_with(scope, Name(name), Id(id), |_, _, _| {
                (v8_name.into(), v8_id.into())
            });
            // Reverse mapping: id -> name
            imap.insert_with(scope, Id(id), Name(name), |_, _, _| {
                (v8_id.into(), v8_name.into())
            });

            #[cfg(test)]
            {
                use crate::analysis::ddsa_lib::common::v8_string;
                use crate::analysis::ddsa_lib::test_utils::{
                    format_ts_lang_pointer, KEY_TS_LANGUAGE_PTR,
                };
                // Set an additional entry that can be used to check equivalence of the
                // tree-sitter language used to generate this metadata map.
                let v8_key = v8_interned(scope, KEY_TS_LANGUAGE_PTR);
                let v8_value = v8_string(scope, &format_ts_lang_pointer(ts_language));
                let opened = imap.v8_map().open(scope);
                opened.set(scope, v8_key.into(), v8_value.into());
            }
        });
    imap
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::context::ts_lang;
    use crate::analysis::ddsa_lib::test_utils::{attach_as_global, cfg_test_v8, try_execute};
    use crate::analysis::tree_sitter::get_tree_sitter_language;
    use crate::model::common::Language;

    /// Tests the metadata mapping for a tree-sitter language's "node kind"
    #[test]
    fn metadata_node_kind() {
        let mut runtime = cfg_test_v8().deno_core_rt();
        let scope = &mut runtime.handle_scope();
        let ts_lang = get_tree_sitter_language(&Language::JavaScript);
        let metadata = ts_lang::Metadata::new(scope, &ts_lang);
        let v8_map = metadata.node_kind_map.as_local(scope);
        attach_as_global(scope, v8_map, "NODE_KIND");

        // (Assertion included to alert if upstream tree-sitter grammar unexpectedly alters metadata)
        assert_eq!(ts_lang.node_kind_for_id(49).unwrap(), "identifier");

        let value = try_execute(scope, "NODE_KIND.get(49);").unwrap();
        assert!(value.is_string() && &value.to_rust_string_lossy(scope) == "identifier");

        let value = try_execute(scope, r#"NODE_KIND.get("identifier");"#).unwrap();
        assert!(value.is_uint32() && value.uint32_value(scope).unwrap() == 49);
    }

    /// Tests the metadata mapping for a tree-sitter language's "field"
    #[test]
    fn metadata_field() {
        let mut runtime = cfg_test_v8().deno_core_rt();
        let scope = &mut runtime.handle_scope();
        let ts_lang = get_tree_sitter_language(&Language::JavaScript);
        let metadata = ts_lang::Metadata::new(scope, &ts_lang);
        let v8_map = metadata.field_map.as_local(scope);
        attach_as_global(scope, v8_map, "FIELD");

        // (Assertion included to alert if upstream tree-sitter grammar unexpectedly alters metadata)
        assert_eq!(ts_lang.field_name_for_id(1).unwrap(), "alias");

        let value = try_execute(scope, "FIELD.get(1);").unwrap();
        assert!(value.is_string() && &value.to_rust_string_lossy(scope) == "alias");

        let value = try_execute(scope, r#"FIELD.get("alias");"#).unwrap();
        assert!(value.is_uint32() && value.uint32_value(scope).unwrap() == 1);
    }
}
