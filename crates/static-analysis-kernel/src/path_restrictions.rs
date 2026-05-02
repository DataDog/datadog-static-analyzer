use globset::{GlobSet, GlobSetBuilder};
use indexmap::IndexMap;

use crate::config::common::{PathConfig, PathPattern, RulesetConfig};
use common::model::diff_aware::DiffAware;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A `PathConfig` with cached GlobSets for fast bulk matching against many
/// glob patterns. `rule_applies` is on the per (file, rule) hot path; the
/// stock `PathConfig::allows_file` iterates patterns one-at-a-time which
/// becomes ~1 s wall on a 271 k-file scan with ~135 patterns.
#[derive(Default, Clone)]
struct CompiledPathConfig {
    /// Original config, kept for DiffAware digest generation.
    config: PathConfig,
    /// Compiled GlobSet for the ignore patterns' globs (None if no globs).
    ignore_globs: Option<GlobSet>,
    /// Prefix-only patterns from ignore (extracted once).
    ignore_prefixes: Vec<PathBuf>,
    /// Compiled GlobSet for the only patterns' globs.
    only_globs: Option<GlobSet>,
    /// Prefix-only patterns from only (None if `config.only` is None).
    only_prefixes: Option<Vec<PathBuf>>,
}

impl CompiledPathConfig {
    fn from_config(config: PathConfig) -> Self {
        let ignore_globs = build_globset(&config.ignore);
        let ignore_prefixes = collect_prefixes(&config.ignore);
        let only_globs = config.only.as_ref().and_then(|p| build_globset(p));
        let only_prefixes = config
            .only
            .as_ref()
            .map(|p| collect_prefixes(p));
        Self {
            config,
            ignore_globs,
            ignore_prefixes,
            only_globs,
            only_prefixes,
        }
    }

    /// Same semantics as `PathConfig::allows_file` but uses cached
    /// GlobSets for the bulk glob match. ~10× faster on a many-pattern
    /// config.
    fn allows_file(&self, file_name: &str) -> bool {
        let in_ignore = self
            .ignore_globs
            .as_ref()
            .map(|s| s.is_match(file_name))
            .unwrap_or(false)
            || {
                let p = Path::new(file_name);
                self.ignore_prefixes.iter().any(|prefix| p.starts_with(prefix))
            };
        if in_ignore {
            return false;
        }
        match (&self.only_globs, &self.only_prefixes) {
            (None, None) => {
                // `config.only` was None → no constraint.
                self.config.only.is_none()
            }
            _ => {
                let glob_hit = self
                    .only_globs
                    .as_ref()
                    .map(|s| s.is_match(file_name))
                    .unwrap_or(false);
                let prefix_hit = self
                    .only_prefixes
                    .as_ref()
                    .map(|prefixes| {
                        let p = Path::new(file_name);
                        prefixes.iter().any(|prefix| p.starts_with(prefix))
                    })
                    .unwrap_or(false);
                glob_hit || prefix_hit
            }
        }
    }
}

impl DiffAware for CompiledPathConfig {
    fn generate_diff_aware_digest(&self) -> String {
        self.config.generate_diff_aware_digest()
    }
}

fn build_globset(patterns: &[PathPattern]) -> Option<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    let mut added_any = false;
    for pattern in patterns {
        if let Some(matcher) = &pattern.glob {
            builder.add(matcher.glob().clone());
            added_any = true;
        }
    }
    if !added_any {
        return None;
    }
    builder.build().ok()
}

fn collect_prefixes(patterns: &[PathPattern]) -> Vec<PathBuf> {
    patterns
        .iter()
        .filter(|p| !p.prefix.as_os_str().is_empty())
        .map(|p| p.prefix.clone())
        .collect()
}

#[derive(Default, Clone)]
struct RestrictionsForRuleset {
    /// Per-rule path restrictions, with cached GlobSets.
    rules: HashMap<String, CompiledPathConfig>,
    /// Path restrictions for this ruleset, with cached GlobSets.
    paths: CompiledPathConfig,
}

impl DiffAware for RestrictionsForRuleset {
    fn generate_diff_aware_digest(&self) -> String {
        let paths = self.paths.generate_diff_aware_digest();
        let mut rules: Vec<String> = self
            .rules
            .iter()
            .map(|(k, v)| format!("{}:{}", k, v.generate_diff_aware_digest()))
            .collect::<Vec<String>>();
        rules.sort();
        let rules_str = rules.join(",");

        format!("{}:{}", paths, rules_str)
    }
}


/// An object that provides operations to filter rules by the path of the file to check.
#[derive(Default, Clone)]
pub struct PathRestrictions {
    /// Per-ruleset restrictions.
    rulesets: HashMap<String, RestrictionsForRuleset>,
}

impl DiffAware for PathRestrictions {
    fn generate_diff_aware_digest(&self) -> String {
        let mut res: Vec<String> = self
            .rulesets
            .iter()
            .map(|(k, v)| format!("{}:{}", k, v.generate_diff_aware_digest()))
            .collect::<Vec<String>>();
        res.sort();

        res.join(",")
    }
}

impl PathRestrictions {
    /// Builds a `PathRestrictions` from a map of ruleset configurations.
    pub fn from_ruleset_configs(rulesets: &IndexMap<String, RulesetConfig>) -> PathRestrictions {
        let mut out = PathRestrictions::default();
        for (name, ruleset_config) in rulesets {
            let mut restriction = RestrictionsForRuleset {
                paths: CompiledPathConfig::from_config(ruleset_config.paths.clone()),
                ..Default::default()
            };
            for (name, rule_config) in &ruleset_config.rules {
                restriction.rules.insert(
                    name.clone(),
                    CompiledPathConfig::from_config(rule_config.paths.clone()),
                );
            }
            out.rulesets.insert(name.clone(), restriction);
        }
        out
    }

    /// Returns whether the given rule applies to a file.
    pub fn rule_applies(&self, rule_name: &str, file_path: &str) -> bool {
        let (ruleset, short_name) = split_rule_name(rule_name);
        match self.rulesets.get(ruleset) {
            None => true,
            Some(restrictions) => {
                restrictions.paths.allows_file(file_path)
                    && match restrictions.rules.get(short_name) {
                        None => true,
                        Some(paths) => paths.allows_file(file_path),
                    }
            }
        }
    }
}

fn split_rule_name(name: &str) -> (&str, &str) {
    match name.split_once('/') {
        None => ("", name),
        Some((ruleset, short_name)) => (ruleset, short_name),
    }
}

#[cfg(test)]
mod tests {
    use crate::config::common::{PathConfig, RuleConfig, RulesetConfig};
    use crate::path_restrictions::PathRestrictions;
    use common::model::diff_aware::DiffAware;

    // By default, everything is included.
    #[test]
    fn empty_restrictions() {
        let config =
            indexmap::IndexMap::from([("defined-ruleset".to_string(), RulesetConfig::default())]);
        let restrictions = PathRestrictions::from_ruleset_configs(&config);
        assert!(&restrictions.rule_applies("defined-ruleset/any-rule", "src/main.go"));
        assert!(restrictions.rule_applies("other-ruleset/any-rule", "src/main.go"));
    }

    // Can include and exclude rulesets.
    #[test]
    fn ruleset_restrictions() {
        let config = indexmap::IndexMap::from([
            (
                "ignores-test".to_string(),
                RulesetConfig {
                    paths: PathConfig {
                        ignore: vec!["test/**".to_string().into()],
                        only: None,
                    },
                    rules: indexmap::IndexMap::new(),
                },
            ),
            (
                "only-code".to_string(),
                RulesetConfig {
                    paths: PathConfig {
                        ignore: vec![],
                        only: Some(vec!["*/code/**".to_string().into()]),
                    },
                    rules: indexmap::IndexMap::new(),
                },
            ),
            (
                "test-but-not-code".to_string(),
                RulesetConfig {
                    paths: PathConfig {
                        ignore: vec!["*/code/**".to_string().into()],
                        only: Some(vec!["test/**".to_string().into()]),
                    },
                    rules: indexmap::IndexMap::new(),
                },
            ),
        ]);
        let restrictions = PathRestrictions::from_ruleset_configs(&config);
        assert!(!&restrictions.rule_applies("ignores-test/any-rule", "test/main.go"));
        assert!(!restrictions.rule_applies("only-code/any-rule", "test/main.go"));
        assert!(restrictions.rule_applies("test-but-not-code/any-rule", "test/main.go"));
        assert!(restrictions.rule_applies("any-ruleset/any-rule", "test/main.go"));
        assert!(restrictions.rule_applies("ignores-test/any-rule", "uno/code/proto.go"));
        assert!(restrictions.rule_applies("only-code/any-rule", "uno/code/proto.go"));
        assert!(!restrictions.rule_applies("test-but-not-code/any-rule", "uno/code/proto.go"));
        assert!(restrictions.rule_applies("any-ruleset/any-rule", "uno/code/proto.go"));
        assert!(!restrictions.rule_applies("ignores-test/any-rule", "test/code/proto_test.go"));
        assert!(restrictions.rule_applies("only-code/any-rule", "test/code/proto_test.go"));
        assert!(!restrictions.rule_applies("test-but-not-code/any-rule", "test/code/proto_test.go"));
        assert!(restrictions.rule_applies("any-ruleset/any-rule", "test/code/proto_test.go"));
    }

    // Can include and exclude individual rules.
    #[test]
    fn rule_restrictions() {
        let config = indexmap::IndexMap::from([(
            "a-ruleset".to_string(),
            RulesetConfig {
                paths: PathConfig::default(),
                rules: indexmap::IndexMap::from([
                    (
                        "ignores-test".to_string(),
                        RuleConfig {
                            paths: PathConfig {
                                ignore: vec!["test/**".to_string().into()],
                                only: None,
                            },
                            arguments: Default::default(),
                            severity: None,
                            category: None,
                        },
                    ),
                    (
                        "only-code".to_string(),
                        RuleConfig {
                            paths: PathConfig {
                                ignore: vec![],
                                only: Some(vec!["*/code/**".to_string().into()]),
                            },
                            arguments: Default::default(),
                            severity: None,
                            category: None,
                        },
                    ),
                    (
                        "test-but-not-code".to_string(),
                        RuleConfig {
                            paths: PathConfig {
                                ignore: vec!["*/code/**".to_string().into()],
                                only: Some(vec!["test/**".to_string().into()]),
                            },
                            arguments: Default::default(),
                            severity: None,
                            category: None,
                        },
                    ),
                ]),
            },
        )]);
        let restrictions = PathRestrictions::from_ruleset_configs(&config);
        assert!(!restrictions.rule_applies("a-ruleset/ignores-test", "test/main.go"));
        assert!(!restrictions.rule_applies("a-ruleset/only-code", "test/main.go"));
        assert!(restrictions.rule_applies("a-ruleset/test-but-not-code", "test/main.go"));
        assert!(restrictions.rule_applies("a-ruleset/any-ruleset", "test/main.go"));
        assert!(restrictions.rule_applies("a-ruleset/ignores-test", "uno/code/proto.go"));
        assert!(restrictions.rule_applies("a-ruleset/only-code", "uno/code/proto.go"));
        assert!(!restrictions.rule_applies("a-ruleset/test-but-not-code", "uno/code/proto.go"));
        assert!(restrictions.rule_applies("a-ruleset/any-ruleset", "uno/code/proto.go"));
        assert!(!restrictions.rule_applies("a-ruleset/ignores-test", "test/code/proto_test.go"));
        assert!(restrictions.rule_applies("a-ruleset/only-code", "test/code/proto_test.go"));
        assert!(
            !restrictions.rule_applies("a-ruleset/test-but-not-code", "test/code/proto_test.go")
        );
        assert!(restrictions.rule_applies("a-ruleset/any-ruleset", "test/code/proto_test.go"));
    }

    #[test]
    fn rule_restrictions_generate_diff_aware_digest() {
        let mut config1 = indexmap::IndexMap::new();
        config1.insert(
            "a-ruleset".to_string(),
            RulesetConfig {
                paths: PathConfig::default(),
                rules: indexmap::IndexMap::from([(
                    "ignores-test2".to_string(),
                    RuleConfig {
                        paths: PathConfig {
                            ignore: vec!["test2/**".to_string().into()],
                            only: None,
                        },
                        arguments: Default::default(),
                        severity: None,
                        category: None,
                    },
                )]),
            },
        );
        config1.insert(
            "b-ruleset".to_string(),
            RulesetConfig {
                paths: PathConfig::default(),
                rules: indexmap::IndexMap::from([(
                    "ignores-test".to_string(),
                    RuleConfig {
                        paths: PathConfig {
                            ignore: vec!["test/**".to_string().into()],
                            only: None,
                        },
                        arguments: Default::default(),
                        severity: None,
                        category: None,
                    },
                )]),
            },
        );

        let mut config2 = indexmap::IndexMap::new();
        config2.insert(
            "b-ruleset".to_string(),
            RulesetConfig {
                paths: PathConfig::default(),
                rules: indexmap::IndexMap::from([(
                    "ignores-test".to_string(),
                    RuleConfig {
                        paths: PathConfig {
                            ignore: vec!["test/**".to_string().into()],
                            only: None,
                        },
                        arguments: Default::default(),
                        severity: None,
                        category: None,
                    },
                )]),
            },
        );
        config2.insert(
            "a-ruleset".to_string(),
            RulesetConfig {
                paths: PathConfig::default(),
                rules: indexmap::IndexMap::from([(
                    "ignores-test2".to_string(),
                    RuleConfig {
                        paths: PathConfig {
                            ignore: vec!["test2/**".to_string().into()],
                            only: None,
                        },
                        arguments: Default::default(),
                        severity: None,
                        category: None,
                    },
                )]),
            },
        );

        let restrictions1 = PathRestrictions::from_ruleset_configs(&config1);
        let restrictions2 = PathRestrictions::from_ruleset_configs(&config2);
        assert_eq!("a-ruleset:::ignores-test2::test2/**:test2/**,b-ruleset:::ignores-test::test/**:test/**".to_string(), restrictions1.generate_diff_aware_digest());
        assert_eq!(
            restrictions1.generate_diff_aware_digest(),
            restrictions2.generate_diff_aware_digest()
        );
    }

    // Can combine inclusion and exclusions for rules and rulesets.
    #[test]
    fn ruleset_and_rule_restrictions() {
        let config = indexmap::IndexMap::from([(
            "only-test".to_string(),
            RulesetConfig {
                paths: PathConfig {
                    only: Some(vec!["test/**".to_string().into()]),
                    ignore: vec![],
                },
                rules: indexmap::IndexMap::from([(
                    "ignores-code".to_string(),
                    RuleConfig {
                        paths: PathConfig {
                            ignore: vec!["*/code/**".to_string().into()],
                            only: None,
                        },
                        arguments: Default::default(),
                        severity: None,
                        category: None,
                    },
                )]),
            },
        )]);
        let restrictions = PathRestrictions::from_ruleset_configs(&config);
        assert!(restrictions.rule_applies("only-test/ignores-code", "test/main.go"));
        assert!(restrictions.rule_applies("only-test/any-rule", "test/main.go"));
        assert!(restrictions.rule_applies("any-ruleset/ignores-code", "test/main.go"));
        assert!(restrictions.rule_applies("any-ruleset/any-rule", "test/main.go"));
        assert!(!restrictions.rule_applies("only-test/ignores-code", "test/code/proto_test.go"));
        assert!(restrictions.rule_applies("only-test/any-rule", "test/code/proto_test.go"));
        assert!(restrictions.rule_applies("any-ruleset/ignores-code", "test/code/proto_test.go"));
        assert!(restrictions.rule_applies("any-ruleset/any-rule", "test/code/proto_test.go"));
        assert!(!restrictions.rule_applies("only-test/ignores-code", "foo/code/main.go"));
        assert!(!restrictions.rule_applies("only-test/any-rule", "foo/code/main.go"));
        assert!(restrictions.rule_applies("any-ruleset/ignores-code", "foo/code/main.go"));
        assert!(restrictions.rule_applies("any-ruleset/any-rule", "foo/code/main.go"));
    }

    // Can do prefix and glob pattern matching.
    #[test]
    fn prefix_and_glob_matching() {
        let config = indexmap::IndexMap::from([
            (
                "only-test-starstar-foo-glob".to_string(),
                RulesetConfig {
                    paths: PathConfig {
                        only: Some(vec!["test/**/foo.go".to_string().into()]),
                        ignore: vec![],
                    },
                    ..Default::default()
                },
            ),
            (
                "ignore-uno-code-prefix".to_string(),
                RulesetConfig {
                    paths: PathConfig {
                        only: None,
                        ignore: vec!["uno/code".to_string().into()],
                    },
                    ..Default::default()
                },
            ),
        ]);
        let restrictions = PathRestrictions::from_ruleset_configs(&config);
        assert!(!restrictions.rule_applies("only-test-starstar-foo-glob/rule", "test/main.go"));
        assert!(restrictions.rule_applies("ignore-uno-code-prefix/rule", "test/main.go"));
        assert!(restrictions.rule_applies("only-test-starstar-foo-glob/rule", "test/main/foo.go"));
        assert!(restrictions.rule_applies("ignore-uno-code-prefix/rule", "test/main/foo.go"));
        assert!(!restrictions.rule_applies("only-test-starstar-foo-glob/rule", "uno/code/proto.go"));
        assert!(!restrictions.rule_applies("ignore-uno-code-prefix/rule", "uno/code/proto.go"));
        assert!(!restrictions.rule_applies("only-test-starstar-foo-glob/rule", "uno/proto.go"));
        assert!(restrictions.rule_applies("ignore-uno-code-prefix/rule", "uno/proto.go"));
    }
}
