// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::common::{v8_interned, v8_uint, DDSAJsRuntimeError};
use deno_core::v8;
use deno_core::v8::HandleScope;
use indexmap::{Equivalent, IndexMap};
use std::hash::Hash;

// A collection of building blocks to build data structures with state synced between Rust and v8.

/// Takes a reference to a Rust value and converts it into a [`v8::Value`], potentially allocating.
pub trait RustConverter {
    type Item;

    fn convert_to<'s>(
        &self,
        scope: &mut HandleScope<'s>,
        value: &Self::Item,
    ) -> v8::Local<'s, v8::Value>;
}

/// Takes a [`v8::Local<v8::Value>`] and converts it into an owned Rust value.
pub trait V8Converter {
    type Item;
    type Error;

    fn try_convert_from<'s>(
        &self,
        scope: &mut HandleScope<'s>,
        value: v8::Local<'s, v8::Value>,
    ) -> Result<Self::Item, Self::Error>;
}

/// A [`Vec<T>`] that is mirrored one-way to a [`v8::Array`].
///
/// # Synchronization
/// This data structure is automatically synced from Rust to v8 upon every Rust mutation.
/// Warning: the state between Rust and V8 will be out of sync if the underlying `v8::Array` is
/// mutated (e.g. if a JavaScript context mutates the array or any of its elements directly).
#[derive(Debug)]
pub struct MirroredVec<T, C> {
    converter: C,
    vec: Vec<T>,
    v8_array: v8::Global<v8::Array>,
    s_length: v8::Global<v8::String>,
}

impl<T, C> MirroredVec<T, C>
where
    C: RustConverter<Item = T>,
{
    /// Constructs a new, empty `MirroredVec`.
    pub fn new(converter: C, scope: &mut HandleScope) -> Self {
        Self::with_capacity(converter, scope, 0)
    }

    /// Constructs a new, empty `MirroredVec` with at least the specified capacity.
    pub fn with_capacity(converter: C, scope: &mut HandleScope, capacity: u32) -> Self {
        let s_length = v8_interned(scope, "length");
        // We intentionally pass in "0" for length (and not `capacity`) due to the potential
        // for v8 to classify it as a "holey" array (and trigger de-optimizations).
        let v8_array = v8::Array::new(scope, 0);

        // v8 provides no API for pre-allocating, so we fill the array with undefined and then reset
        // its length to implement this behavior.
        if capacity > 0 {
            let undefined = v8::undefined(scope);
            for i in (0..capacity).rev() {
                v8_array.set_index(scope, i, undefined.into());
            }
            let zero = v8_uint(scope, 0);
            v8_array.set(scope, s_length.into(), zero.into());
        }

        let s_length = v8::Global::new(scope, s_length);
        let v8_array = v8::Global::new(scope, v8_array);

        Self {
            converter,
            vec: Vec::with_capacity(capacity as usize),
            v8_array,
            s_length,
        }
    }

    /// Sets the data in the vector to `data` and mirrors the values to v8. Note that no deduplication
    /// attempt is made -- the entire array will be cleared and re-written in both Rust and v8.
    ///
    /// Existing v8 values will be released to v8's garbage collector.
    pub fn set_data(&mut self, scope: &mut HandleScope, data: impl Into<Vec<T>>) {
        let v8_array = self.v8_array.open(scope);
        let prev_len = v8_array.length() as usize;

        let data = data.into();
        // 1. Insert the new `data` elements, replacing existing elements if they exist.
        for (idx, element) in data.iter().enumerate() {
            let v8_value = self.converter.convert_to(scope, element);
            v8_array.set_index(scope, idx as u32, v8_value);
        }
        // 2. Delete any excess v8 elements.
        if prev_len > data.len() {
            let undefined = v8::undefined(scope);
            for idx in (data.len()..prev_len).rev() {
                v8_array.set_index(scope, idx as u32, undefined.into());
            }
            let length_prop = v8::Local::new(scope, &self.s_length);
            let len_smi = v8_uint(scope, data.len() as u32);
            v8_array.set(scope, length_prop.into(), len_smi.into());
        }
        // 3. Update the Vec, preserving its allocation.
        self.vec.clear();
        self.vec.extend(data);
    }

    /// Clears the array.
    ///
    /// Garbage collection behavior follows that of [`MirroredVec::set_data`].
    #[inline(always)]
    pub fn clear(&mut self, scope: &mut HandleScope) {
        self.set_data(scope, vec![]);
    }

    /// Returns a reference to the element at the given index.
    #[inline(always)]
    pub fn get(&self, index: usize) -> Option<&T> {
        self.vec.get(index)
    }

    /// Returns the number of elements in the vector.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.vec.len()
    }

    /// Returns true if the vector is empty.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.vec.len() == 0
    }

    /// Returns a handle to the v8 element at the given index.
    #[cfg(test)]
    pub fn get_v8<'s>(&self, scope: &mut HandleScope<'s>, index: u32) -> v8::Local<'s, v8::Value> {
        let index = v8_uint(scope, index);
        self.v8_array.open(scope).get(scope, index.into()).unwrap()
    }

    /// Inspects the underlying [`v8::Array`] to return the number of elements it contains.
    #[cfg(test)]
    fn v8_len(&self, scope: &mut HandleScope) -> usize {
        let v8_array = self.v8_array.open(scope);
        v8_array.length() as usize
    }
}

/// An [`IndexMap<K, V>`] that is mirrored one-way to a [`v8::Map`].
///
/// # Synchronization
/// This data structure is automatically synced from Rust to v8 upon every Rust mutation.
/// Warning: the state between Rust and V8 will be out of sync if the underlying `v8::Map` is
/// mutated (e.g. if a JavaScript context mutates the map or any of its entries directly).
#[derive(Debug)]
pub struct MirroredIndexMap<K, V> {
    imap: IndexMap<K, V>,
    v8_map: v8::Global<v8::Map>,
}

impl<K, V> MirroredIndexMap<K, V>
where
    K: Eq + Hash,
    V: Eq,
{
    /// Constructs a new, empty `MirroredIndexMap`.
    pub fn new(scope: &mut HandleScope) -> Self {
        Self::with_capacity(scope, 0)
    }

    /// Creates a new, empty `MirroredIndexMap` with at least the specified capacity.
    /// Note: the capacity is allocated for the Rust `IndexMap` only, not the `v8::Map`.
    pub fn with_capacity(scope: &mut HandleScope, capacity: usize) -> Self {
        let v8_map = v8::Map::new(scope);
        let v8_map = v8::Global::new(scope, v8_map);
        let imap = IndexMap::with_capacity(capacity);
        Self { imap, v8_map }
    }

    /// Gets the item index and a reference to the key and value for a given key.
    #[inline(always)]
    pub fn get_full<Q>(&self, key: &Q) -> Option<(usize, &K, &V)>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.imap.get_full(key)
    }

    /// Gets a key-value pair at the given index.
    #[inline(always)]
    pub fn get_index(&self, index: usize) -> Option<(&K, &V)> {
        self.imap.get_index(index)
    }

    /// Inserts a key-value pair into the map, returning the used index.
    ///
    /// If an equivalent key already existed in the map, the entry will be updated in place (i.e.
    /// the key will not be updated), and the existing value will be returned as `Some(V)`.
    pub fn insert_with<'s, G>(
        &mut self,
        scope: &mut HandleScope<'s>,
        key: K,
        value: V,
        kv_generator: G,
    ) -> (usize, Option<V>)
    where
        G: FnOnce(
            &mut HandleScope<'s>,
            &K,
            &V,
        ) -> (v8::Local<'s, v8::Value>, v8::Local<'s, v8::Value>),
    {
        let (index, existing) = self.imap.insert_full(key, value);
        let (current_key, current_value) = self.imap.get_index(index).expect("should exist now");
        // Only update the v8 value if the existing value is different from the newly-inserted value.
        if existing.as_ref() != Some(current_value) {
            let (v8_key, v8_value) = kv_generator(scope, current_key, current_value);
            self.v8_map
                .open(scope)
                .set(scope, v8_key, v8_value)
                .expect("v8 map should be insertable");
        }

        (index, existing)
    }

    /// Removes all the elements in the map, retaining the existing capacity across Rust and v8.
    pub fn clear(&mut self, scope: &mut HandleScope) {
        if self.is_empty() {
            return;
        }
        self.imap.clear();
        self.v8_map.open(scope).clear();
    }

    /// Returns a local handle to the underlying [`v8::Global`] map.
    #[inline(always)]
    pub fn as_local<'s>(&self, scope: &mut HandleScope<'s>) -> v8::Local<'s, v8::Map> {
        v8::Local::new(scope, &self.v8_map)
    }

    pub fn v8_map(&self) -> &v8::Global<v8::Map> {
        &self.v8_map
    }

    /// Returns the number of key-value pairs in the map.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.imap.len()
    }

    /// Returns true if the map is empty.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[cfg(test)]
    pub fn get_v8_int<'s>(
        &self,
        scope: &mut HandleScope<'s>,
        key: &str,
    ) -> v8::Local<'s, v8::Integer> {
        let value = self.get_v8(scope, key);
        value.try_into().unwrap()
    }

    #[cfg(test)]
    pub fn get_v8<'s>(&self, scope: &mut HandleScope<'s>, key: &str) -> v8::Local<'s, v8::Value> {
        let key = v8_interned(scope, key);
        self.v8_map.open(scope).get(scope, key.into()).unwrap()
    }
}

/// A [`v8::Array`] that is mirrored one-way to a [`Vec<T>`].
///
/// # Synchronization
/// This data structure is synced from v8 to Rust on a pull-basis. The `Vec<T>` will get out of sync
/// if the underlying `v8::Array` is mutated without manually re-syncing the data.
#[derive(Debug)]
pub struct SyncedV8Array<T, C> {
    converter: C,
    vec: Vec<T>,
    v8_array: v8::Global<v8::Array>,
    s_length: v8::Global<v8::String>,
}

impl<T, C> SyncedV8Array<T, C>
where
    C: V8Converter<Item = T, Error = DDSAJsRuntimeError>,
{
    /// Constructs a new, empty `SyncedV8Array`.
    pub fn new(converter: C, scope: &mut HandleScope, array: v8::Global<v8::Array>) -> Self {
        Self::with_capacity(converter, scope, array, 0)
    }

    /// Constructs a new, empty `SyncedV8Array` with at least the specified capacity.
    pub fn with_capacity(
        converter: C,
        scope: &mut HandleScope,
        array: v8::Global<v8::Array>,
        capacity: u32,
    ) -> Self {
        let s_length = v8_interned(scope, "length");
        let s_length = v8::Global::new(scope, s_length);

        Self {
            converter,
            vec: Vec::with_capacity(capacity as usize),
            v8_array: array,
            s_length,
        }
    }

    /// Provides a [`v8::Local`] handle to the underlying [`v8::Global`] array.
    #[inline(always)]
    pub fn as_local<'s>(&self, scope: &mut HandleScope<'s>) -> v8::Local<'s, v8::Array> {
        v8::Local::new(scope, &self.v8_array)
    }

    /// Pulls elements from the [`v8::Array`], draining it in the process. Returns the elements into =
    /// a collected `Vec`, or an error if any of the elements couldn't be converted into a [`T`].
    ///
    /// NOTE: To access borrowed values without draining the `v8::Array`, use [`sync_read`](Self::sync_read).
    pub fn drain_collect(&mut self, scope: &mut HandleScope) -> Result<Vec<T>, DDSAJsRuntimeError> {
        self.sync_data(scope)?;
        let mut collected = Vec::with_capacity(self.vec.len());
        // Prevent dropping into v8 unless necessary
        if self.vec.is_empty() {
            return Ok(collected);
        }
        self.clear_v8(scope);
        collected.append(&mut self.vec);
        Ok(collected)
    }

    /// Clears the `v8::Array`.
    pub fn clear(&mut self, scope: &mut HandleScope) {
        self.clear_v8(scope);
        self.vec.clear();
    }

    /// Syncs the data from v8, returning a reference to it.
    ///
    /// To mutably take owned values, use [`drain_collect`](Self::drain_collect).
    pub fn sync_read(&mut self, scope: &mut HandleScope) -> Result<&[T], DDSAJsRuntimeError> {
        self.sync_data(scope)?;
        Ok(self.vec.as_slice())
    }

    /// Syncs the data from the `v8::Array` to the `Vec<T>`.
    ///
    /// Note: Equivalence of elements is not checked, so this will always re-convert the v8 values via the `converter`.
    fn sync_data(&mut self, scope: &mut HandleScope) -> Result<(), DDSAJsRuntimeError> {
        let v8_array = self.v8_array.open(scope);
        let v8_len = v8_array.length() as usize;

        self.vec.clear();
        self.vec
            .reserve_exact(v8_len.saturating_sub(self.vec.len()));
        for idx in 0..v8_len {
            let v8_value = v8_array
                .get_index(scope, idx as u32)
                .expect("index should have been bounds checked");
            let rust_value = self.converter.try_convert_from(scope, v8_value)?;
            self.vec.push(rust_value);
        }
        Ok(())
    }

    /// Clears the underlying `v8::Array`, preserving its allocation.
    fn clear_v8(&self, scope: &mut HandleScope) {
        let v8_array = self.v8_array.open(scope);
        let undefined = v8::undefined(scope);
        for idx in (0..v8_array.length()).rev() {
            v8_array.set_index(scope, idx, undefined.into());
        }
        let length_prop = v8::Local::new(scope, &self.s_length);
        let zero = v8_uint(scope, 0);
        v8_array.set(scope, length_prop.into(), zero.into());
    }

    #[cfg(test)]
    fn v8_len(&self, scope: &mut HandleScope) -> usize {
        self.v8_array.open(scope).length() as usize
    }
}

/// Implements the [`RustConverter`] trait for the given struct and type.
///
/// # Example
/// ```text
/// struct IntConverter;
/// rust_converter!((IntConverter, i32), |&self, scope, value| {
///     v8::Integer::new(scope, *value).into()
/// });
/// ```
#[macro_export]
macro_rules! rust_converter {
  (($r#struct:ty, $ty:ty), |&$self:ident, $scope:ident, $value:ident| $convert_expr:expr) => {
      impl $crate::analysis::ddsa_lib::v8_ds::RustConverter for $r#struct {
          type Item = $ty;
          fn convert_to<'s>(
              &$self,
              $scope: &mut HandleScope<'s>,
              $value: &Self::Item,
          ) -> v8::Local<'s, v8::Value> {
              $convert_expr
          }
      }
  };
}

/// Implements the [`V8Converter`] trait for the given struct and type.
///
/// # Example
/// ```text
/// struct ObjConverter;
/// struct Object {
///     key_name: String,
/// }
/// v8_converter!((ObjConverter, Result<Object, &'static str>), |&self, scope, value| {
///     let obj: v8::Local<v8::Object> = value.try_into().unwrap();
///     let v8_key = v8::String::new(scope, "key_name").unwrap();
///     let v8_value = obj.get(scope, v8_key.into()).ok_or("key not present")?;
///     let v8_str = v8_value.to_string(scope).ok_or("value is not a string")?;
///     let value = v8_str.to_rust_string_lossy(scope);
///     Ok(Object { key_name: value })
/// });
/// ```
#[macro_export]
macro_rules! v8_converter {
  (($r#struct:ident, Result<$ty:ty, $err:ty>), |&$self:ident, $scope:ident, $value:ident| $convert_expr:expr) => {
      impl $crate::analysis::ddsa_lib::v8_ds::V8Converter for $r#struct {
          type Item = $ty;
          type Error = $err;
          fn try_convert_from<'s>(
              &$self,
              $scope: &mut HandleScope<'s>,
              $value: v8::Local<'s, v8::Value>,
          ) -> Result<Self::Item, Self::Error> {
              $convert_expr
          }
      }
  };
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::common::{v8_interned, v8_string, v8_uint, DDSAJsRuntimeError};
    use crate::analysis::ddsa_lib::v8_ds::{MirroredIndexMap, MirroredVec, SyncedV8Array};
    use deno_core::v8::HandleScope;
    use deno_core::{v8, JsRuntime, RuntimeOptions};

    struct IntConverter;
    rust_converter!((IntConverter, i32), |&self, scope, value| {
        v8::Integer::new(scope, *value).into()
    });
    struct StringConverter;
    rust_converter!((StringConverter, String), |&self, scope, value| {
        v8_string(scope, value).into()
    });

    struct ObjConverter;
    #[derive(Debug, Clone, Eq, PartialEq)]
    struct Object {
        pub key_name: String,
    }
    rust_converter!((ObjConverter, Object), |&self, scope, value| {
        let obj = v8::Object::new(scope);
        let v8_key = v8_string(scope, "key_name");
        let v8_value = v8_string(scope, &value.key_name);
        obj.set(scope, v8_key.into(), v8_value.into());
        obj.into()
    });
    #[rustfmt::skip]
    v8_converter!(
        (ObjConverter, Result<Object, DDSAJsRuntimeError>),
        |&self, scope, value| {
            let obj: v8::Local<v8::Object> = value.try_into().unwrap();
            let v8_key = v8::String::new(scope, "key_name").unwrap();
            let v8_value = obj.get(scope, v8_key.into()).ok_or(DDSAJsRuntimeError::Unspecified)?;
            let v8_str = v8_value.to_string(scope).ok_or(DDSAJsRuntimeError::Unspecified)?;
            let value = v8_str.to_rust_string_lossy(scope);
            if value == "undefined" {
                Err(DDSAJsRuntimeError::Unspecified)
            } else {
                Ok(Object { key_name: value })
            }
        }
    );
    impl Object {
        fn new(value: &str) -> Self {
            Self {
                key_name: value.to_string(),
            }
        }
        fn to_v8<'s>(&self, scope: &mut HandleScope<'s>) -> v8::Local<'s, v8::Value> {
            let v8_obj = v8::Object::new(scope);
            let v8_key = v8::String::new(scope, "key_name").unwrap();
            let v8_value = v8::String::new(scope, &self.key_name).unwrap();
            v8_obj.set(scope, v8_key.into(), v8_value.into());
            v8_obj.into()
        }
    }

    /// A v8 key-value generator function for [`MirroredIndexMap`].
    fn default_kv_generator<'s, K: AsRef<str>>(
        scope: &mut HandleScope<'s>,
        key: &K,
        value: &i32,
    ) -> (v8::Local<'s, v8::Value>, v8::Local<'s, v8::Value>) {
        let key = v8_interned(scope, key.as_ref());
        let value = v8_uint(scope, *value as u32);
        (key.into(), value.into())
    }

    fn setup_vec_from_v8(name: &str) -> (JsRuntime, SyncedV8Array<Object, ObjConverter>) {
        let mut rt = JsRuntime::new(RuntimeOptions::default());
        let synced = {
            let scope = &mut rt.handle_scope();
            let v8_array = v8::Array::new(scope, 0);
            let v8_array = v8::Global::new(scope, v8_array);
            let s_name = v8_interned(scope, name);
            let synced = SyncedV8Array::new(ObjConverter, scope, v8_array);
            let ctx = scope.get_current_context();
            let global = ctx.global(scope);
            let v8_synced = synced.as_local(scope);
            global.set(scope, s_name.into(), v8_synced.into());
            synced
        };
        (rt, synced)
    }

    fn execute_script<'s>(
        scope: &mut HandleScope<'s>,
        code: &str,
    ) -> Option<v8::Local<'s, v8::Value>> {
        let code = v8_string(scope, code);
        let script = v8::Script::compile(scope, code, None).unwrap();
        script.run(scope)
    }

    #[test]
    fn mirrored_vec_set_get() {
        let mut runtime = JsRuntime::new(RuntimeOptions::default());
        let scope = &mut runtime.handle_scope();

        let mut synced = MirroredVec::new(IntConverter, scope);
        assert_eq!(synced.v8_len(scope), 0);
        assert_eq!(synced.len(), 0);

        let data = vec![1, 2, 3, 4];
        synced.set_data(scope, data.clone());
        for (i, &val) in data.iter().enumerate().take(synced.len()) {
            let v8_val = synced.get_v8(scope, i as u32);
            assert_eq!(val, data[i]);
            assert_eq!(val, v8_val.int32_value(scope).unwrap());
        }
        assert!(synced.len() == 4 && synced.get(4).is_none());
        assert_eq!(synced.v8_len(scope), 4);
        assert_eq!(synced.get_v8(scope, 4), v8::undefined(scope));
    }

    /// Tests that clear wipes the existing data, preserving the original allocation.
    #[test]
    fn mirrored_vec_clear() {
        let mut runtime = JsRuntime::new(RuntimeOptions::default());
        let scope = &mut runtime.handle_scope();

        let mut synced = MirroredVec::with_capacity(IntConverter, scope, 16);
        let data = vec![1, 2, 3, 4];
        synced.set_data(scope, data);
        assert_eq!(synced.v8_len(scope), 4);
        // Used as a proxy for array capacity -- if the array is the same (i.e. not replaced with a new one),
        // the capacity should be the same.
        let v8_array_id = synced.v8_array.open(scope).get_identity_hash();

        synced.clear(scope);
        assert_eq!(synced.v8_len(scope), 0);
        assert_eq!(synced.len(), 0);
        assert_eq!(synced.vec.capacity(), 16);
        assert_eq!(synced.v8_array.open(scope).get_identity_hash(), v8_array_id);
    }

    /// Tests that existing values are properly cleared when setting the data (tested because we re-use the v8 array).
    #[test]
    fn mirrored_vec_replace() {
        let mut runtime = JsRuntime::new(RuntimeOptions::default());
        let scope = &mut runtime.handle_scope();

        // Long -> Short
        let mut synced = MirroredVec::new(IntConverter, scope);
        synced.set_data(scope, vec![1, 2, 3, 4]);
        synced.set_data(scope, vec![5, 6]);
        assert_eq!(synced.get_v8(scope, 0).int32_value(scope), Some(5));
        assert_eq!(synced.get_v8(scope, 1).int32_value(scope), Some(6));
        assert_eq!(synced.get_v8(scope, 2), v8::undefined(scope));
        // Short -> Long
        let mut synced = MirroredVec::new(IntConverter, scope);
        synced.set_data(scope, vec![1, 2]);
        synced.set_data(scope, vec![5, 6, 7, 8]);
        assert_eq!(synced.get_v8(scope, 2).int32_value(scope), Some(7));
        assert_eq!(synced.get_v8(scope, 3).int32_value(scope), Some(8));
    }

    #[rustfmt::skip]
    #[test]
    fn mirrored_im_insert_with_get_full() {
        let mut runtime = JsRuntime::new(RuntimeOptions::default());
        let scope = &mut runtime.handle_scope();
        let mut synced = MirroredIndexMap::new(scope);

        let data = vec![("abc", 123), ("def", 456), ("ghi", 789)];
        for (idx, (str, int)) in data.iter().enumerate() {
            assert_eq!(synced.insert_with(scope, str.to_string(), *int, default_kv_generator), (idx, None));
        }
        assert_eq!(synced.v8_map.open(scope).size(), 3);
        assert_eq!(synced.len(), 3);
        for (idx, (str, int)) in data.into_iter().enumerate() {
            let v8_value: v8::Local<v8::Value> = v8_uint(scope, int as u32).into();
            assert_eq!(synced.get_v8_int(scope, str), v8_value);
            assert_eq!(synced.get_full(str).unwrap(), (idx, &str.to_string(), &int));
        }
    }

    #[rustfmt::skip]
    #[test]
    fn mirrored_im_replace() {
        let mut runtime = JsRuntime::new(RuntimeOptions::default());
        let scope = &mut runtime.handle_scope();
        let mut synced = MirroredIndexMap::new(scope);

        let (key, value) = ("abc", 123);
        synced.insert_with(scope, key.to_string(), value, default_kv_generator);
        assert_eq!(synced.get_v8_int(scope, key), v8_uint(scope, value as u32));
        assert_eq!(synced.get_full(key).unwrap(), (0, &key.to_string(), &value));
        synced.insert_with(scope, key.to_string(), 456, default_kv_generator);
        assert_eq!(synced.get_v8_int(scope, key), v8_uint(scope, 456));
        assert_eq!(synced.get_full(key).unwrap(), (0, &key.to_string(), &456));

        // However, the v8 value is not changed if the replacement value is equivalent.
        let mut synced = MirroredIndexMap::new(scope);
        let (key, value) = ("123", Object { key_name: "some_value".to_string() });
        synced.insert_with(scope, key, value.clone(), |s, k, v| (v8_string(s, k).into(), v.to_v8(s)));
        let original = synced.get_v8(scope, key);
        synced.insert_with(scope, key, value.clone(), |s, k, v| (v8_string(s, k).into(), v.to_v8(s)));
        let value = synced.get_v8(scope, key);
        assert_eq!(value.get_hash(), original.get_hash());
    }

    #[test]
    fn synced_array_get() {
        let (mut rt, mut synced) = setup_vec_from_v8("ARRAY");
        let scope = &mut rt.handle_scope();
        assert_eq!(synced.sync_read(scope).unwrap().len(), 0);
        let base = vec![Object::new("123"), Object::new("456"), Object::new("789")];
        let code = r#"
ARRAY.push({ key_name: "123" }, { key_name: "456" }, { key_name: "789" });
"#;
        execute_script(scope, code);
        assert_eq!(synced.v8_len(scope), 3);
        assert_eq!(synced.sync_read(scope).unwrap(), base);
        let code = r#"
ARRAY.shift();
"#;
        execute_script(scope, code);
        assert_eq!(synced.vec, base);
        let data = synced.sync_read(scope).unwrap();
        assert_ne!(data, base);
        assert_eq!(data, &base[1..3]);
    }

    #[test]
    fn synced_array_drain() {
        let (mut rt, mut synced) = setup_vec_from_v8("ARRAY");
        let scope = &mut rt.handle_scope();
        let base = vec![Object::new("123"), Object::new("456"), Object::new("789")];
        let code = r#"
ARRAY.push({ key_name: "123" }, { key_name: "456" }, { key_name: "789" });
"#;
        execute_script(scope, code);
        assert_eq!(synced.sync_read(scope).unwrap().len(), 3);
        let original_hash = synced.as_local(scope).get_hash();
        let drained = synced.drain_collect(scope).unwrap();
        assert_eq!(drained, base);
        assert!(synced.vec.is_empty());
        assert_eq!(synced.v8_len(scope), 0);
        assert_eq!(synced.as_local(scope).get_hash(), original_hash);
    }

    #[test]
    fn synced_array_clear() {
        let (mut rt, mut synced) = setup_vec_from_v8("ARRAY");
        let scope = &mut rt.handle_scope();
        let code = r#"
ARRAY.push({ key_name: "123" }, { key_name: "456" }, { key_name: "789" });
"#;
        execute_script(scope, code);
        assert_eq!(synced.v8_len(scope), 3);
        assert_eq!(synced.sync_read(scope).unwrap().len(), 3);
        let original_hash = synced.as_local(scope).get_hash();
        synced.clear(scope);
        assert_eq!(synced.v8_len(scope), 0);
        assert!(synced.vec.is_empty());
        assert_eq!(synced.as_local(scope).get_hash(), original_hash);
    }

    #[test]
    fn synced_array_deserialization_err() {
        let (mut rt, mut synced) = setup_vec_from_v8("ARRAY");
        let scope = &mut rt.handle_scope();
        let code = r#"
ARRAY.push({ key_name: "123" }, { wrong_key: "456" });
"#;
        execute_script(scope, code);
        assert_eq!(synced.v8_len(scope), 2);
        assert!(synced.sync_read(scope).is_err());
        assert_eq!(synced.v8_len(scope), 2);
        let code = r#"
ARRAY.pop();
"#;
        execute_script(scope, code);
        assert_eq!(synced.v8_len(scope), 1);
        assert!(synced.sync_read(scope).is_ok());
    }
}
