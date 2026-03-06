use secrets::model::secret_rule::SecretRule;
use secrets::scanner::build_sds_scanner;
use secrets::Scanner;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, RwLock};

/// A cached SDS scanner with its associated parsed rules and the hash of the rules used to build it.
struct CachedEntry {
    rules_hash: u64,
    scanner: Arc<Scanner>,
    rules: Arc<Vec<SecretRule>>,
}

/// Single-entry cache for the SDS scanner.
/// Stores the most recently built scanner and replaces it when the rule set changes.
///
/// Uses a read-write lock so that cache hits (the common case) only acquire a read lock,
/// allowing concurrent scanning across threads.
pub struct SecretScannerCache(RwLock<Option<CachedEntry>>);

impl std::fmt::Debug for SecretScannerCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretScannerCache").finish()
    }
}

impl SecretScannerCache {
    pub fn new() -> Self {
        Self(RwLock::new(None))
    }

    /// Returns a cached scanner and parsed rules if the rules hash matches,
    /// otherwise builds a new scanner, caches it, and returns it.
    ///
    /// The expensive work (rule deserialization + scanner building) happens outside
    /// any lock to avoid blocking concurrent readers.
    pub fn get_or_build(
        &self,
        raw_rules: &[Box<serde_json::value::RawValue>],
        use_debug: bool,
    ) -> Result<(Arc<Scanner>, Arc<Vec<SecretRule>>), String> {
        let hash = Self::compute_rules_hash(raw_rules);

        // Fast path: read lock only (the common case in IDE usage)
        {
            let guard = self.0.read().unwrap();
            if let Some(entry) = guard.as_ref() {
                if entry.rules_hash == hash {
                    return Ok((Arc::clone(&entry.scanner), Arc::clone(&entry.rules)));
                }
            }
        }

        // Slow path: cache miss - build scanner WITHOUT holding any lock
        let rules: Vec<SecretRule> = raw_rules
            .iter()
            .map(|r| serde_json::from_str(r.get()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to parse rules: {}", e))?;
        let scanner = build_sds_scanner(&rules, use_debug)?;
        let scanner = Arc::new(scanner);
        let rules = Arc::new(rules);

        // Store in cache (write lock held only briefly)
        {
            let mut guard = self.0.write().unwrap();
            *guard = Some(CachedEntry {
                rules_hash: hash,
                scanner: Arc::clone(&scanner),
                rules: Arc::clone(&rules),
            });
        }

        Ok((scanner, rules))
    }

    /// Compute a hash of the raw JSON rules to use as a cache key.
    /// Hashes the raw JSON bytes directly, avoiding deserialization.
    fn compute_rules_hash(raw_rules: &[Box<serde_json::value::RawValue>]) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        raw_rules.len().hash(&mut hasher);
        for rule in raw_rules {
            rule.get().hash(&mut hasher);
        }
        hasher.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(json: &str) -> Box<serde_json::value::RawValue> {
        serde_json::value::RawValue::from_string(json.to_owned()).unwrap()
    }

    fn sample_rules_json() -> Vec<Box<serde_json::value::RawValue>> {
        vec![raw(r#"{"id":"test-rule","sds_id":"sds-123","name":"Test Rule","description":"A test rule","pattern":"FOO(BAR|BAZ)","priority":"medium","default_included_keywords":[],"default_excluded_keywords":[],"look_ahead_character_count":30,"validators":[],"pattern_capture_groups":[]}"#)]
    }

    #[test]
    fn test_cache_hit() {
        let cache = SecretScannerCache::new();
        let rules = sample_rules_json();

        // First call: cache miss, builds scanner
        let (scanner1, parsed_rules1) = cache.get_or_build(&rules, false).unwrap();
        assert_eq!(parsed_rules1.len(), 1);
        assert_eq!(parsed_rules1[0].id, "test-rule");

        // Second call with same rules: cache hit
        let (scanner2, parsed_rules2) = cache.get_or_build(&rules, false).unwrap();
        assert!(Arc::ptr_eq(&scanner1, &scanner2));
        assert!(Arc::ptr_eq(&parsed_rules1, &parsed_rules2));
    }

    #[test]
    fn test_cache_miss_on_different_rules() {
        let cache = SecretScannerCache::new();
        let rules1 = sample_rules_json();

        let (scanner1, _) = cache.get_or_build(&rules1, false).unwrap();

        // Different rules should cause a cache miss
        let rules2 = vec![raw(r#"{"id":"other-rule","sds_id":"sds-456","name":"Other Rule","description":"Another test rule","pattern":"SECRET_[A-Z]+","priority":"high","default_included_keywords":[],"default_excluded_keywords":[],"look_ahead_character_count":30,"validators":[],"pattern_capture_groups":[]}"#)];

        let (scanner2, parsed_rules2) = cache.get_or_build(&rules2, false).unwrap();
        assert!(!Arc::ptr_eq(&scanner1, &scanner2));
        assert_eq!(parsed_rules2[0].id, "other-rule");
    }

    #[test]
    fn test_compute_rules_hash_deterministic() {
        let rules = sample_rules_json();
        let hash1 = SecretScannerCache::compute_rules_hash(&rules);
        let hash2 = SecretScannerCache::compute_rules_hash(&rules);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_rules_hash_different_for_different_rules() {
        let rules1 = sample_rules_json();
        let rules2 = vec![raw(r#"{"id":"different","sds_id":"sds-999","name":"Different","description":"Different","pattern":"DIFFERENT","priority":"low","default_included_keywords":[],"default_excluded_keywords":[],"look_ahead_character_count":30,"validators":[],"pattern_capture_groups":[]}"#)];
        let hash1 = SecretScannerCache::compute_rules_hash(&rules1);
        let hash2 = SecretScannerCache::compute_rules_hash(&rules2);
        assert_ne!(hash1, hash2);
    }
}
