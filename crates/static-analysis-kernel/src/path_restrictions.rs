use indexmap::IndexMap;

use crate::model::config_file::{PathConfig, RulesetConfig};
use std::collections::HashMap;

/// An object that provides operations to filter rules by the path of the file to check.
#[derive(Default, Clone)]
pub struct PathRestrictions {
    /// Per-ruleset restrictions.
    rulesets: HashMap<String, RestrictionsForRuleset>,
}

#[derive(Default, Clone)]
struct RestrictionsForRuleset {
    /// Per-rule path restrictions.
    rules: HashMap<String, PathConfig>,
    /// Path restrictions for this ruleset.
    paths: PathConfig,
}

impl PathRestrictions {
    /// Builds a `PathRestrictions` from a map of ruleset configurations.
    pub fn from_ruleset_configs(rulesets: &IndexMap<String, RulesetConfig>) -> PathRestrictions {
        let mut out = PathRestrictions::default();
        for (name, ruleset_config) in rulesets {
            let mut restriction = RestrictionsForRuleset {
                paths: ruleset_config.paths.clone(),
                ..Default::default()
            };
            for (name, rule_config) in &ruleset_config.rules {
                restriction
                    .rules
                    .insert(name.clone(), rule_config.paths.clone());
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
    use crate::model::config_file::{PathConfig, RuleConfig, RulesetConfig};
    use crate::path_restrictions::PathRestrictions;

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
