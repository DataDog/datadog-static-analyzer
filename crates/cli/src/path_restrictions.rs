use crate::file_utils::is_allowed_by_path_config;
use crate::model::config_file::RulesetConfig;
use std::collections::HashMap;

/// An object that provides operations to filter rules by the path of the file to check.
#[derive(Default, Clone)]
pub struct PathRestrictions<'a> {
    /// Per-ruleset restrictions.
    rulesets: Option<&'a HashMap<String, RulesetConfig>>,
}

impl<'a> PathRestrictions<'a> {
    /// Builds a `PathRestrictions` from a map of ruleset configurations.
    pub fn from_ruleset_configs(
        rulesets: &'a HashMap<String, RulesetConfig>,
    ) -> PathRestrictions<'a> {
        PathRestrictions {
            rulesets: Some(rulesets),
        }
    }

    /// Returns whether the given rule applies to a file.
    pub fn rule_applies(&self, rule_name: &str, file_path: &str) -> bool {
        let (ruleset, short_name) = split_rule_name(rule_name);
        match self.rulesets.and_then(|x| x.get(ruleset)) {
            None => true,
            Some(ruleset_config) => {
                is_allowed_by_path_config(&ruleset_config.paths, file_path)
                    && match ruleset_config.rules.get(short_name) {
                        None => true,
                        Some(rule_config) => {
                            is_allowed_by_path_config(&rule_config.paths, file_path)
                        }
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
    use std::collections::HashMap;

    // By default, everything is included.
    #[test]
    fn empty_restrictions() {
        let config = HashMap::from([("defined-ruleset".to_string(), RulesetConfig::default())]);
        let restrictions = PathRestrictions::from_ruleset_configs(&config);
        assert!(&restrictions.rule_applies("defined-ruleset/any-rule", "src/main.go"));
        assert!(restrictions.rule_applies("other-ruleset/any-rule", "src/main.go"));
    }

    // Can include and exclude rulesets.
    #[test]
    fn ruleset_restrictions() {
        let config = HashMap::from([
            (
                "ignores-test".to_string(),
                RulesetConfig {
                    paths: PathConfig {
                        ignore: vec!["test/**".to_string()],
                        only: None,
                    },
                    rules: HashMap::new(),
                },
            ),
            (
                "only-code".to_string(),
                RulesetConfig {
                    paths: PathConfig {
                        ignore: vec![],
                        only: Some(vec!["*/code/**".to_string()]),
                    },
                    rules: HashMap::new(),
                },
            ),
            (
                "test-but-not-code".to_string(),
                RulesetConfig {
                    paths: PathConfig {
                        ignore: vec!["*/code/**".to_string()],
                        only: Some(vec!["test/**".to_string()]),
                    },
                    rules: HashMap::new(),
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
        let config = HashMap::from([(
            "a-ruleset".to_string(),
            RulesetConfig {
                paths: PathConfig::default(),
                rules: HashMap::from([
                    (
                        "ignores-test".to_string(),
                        RuleConfig {
                            paths: PathConfig {
                                ignore: vec!["test/**".to_string()],
                                only: None,
                            },
                        },
                    ),
                    (
                        "only-code".to_string(),
                        RuleConfig {
                            paths: PathConfig {
                                ignore: vec![],
                                only: Some(vec!["*/code/**".to_string()]),
                            },
                        },
                    ),
                    (
                        "test-but-not-code".to_string(),
                        RuleConfig {
                            paths: PathConfig {
                                ignore: vec!["*/code/**".to_string()],
                                only: Some(vec!["test/**".to_string()]),
                            },
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
        let config = HashMap::from([(
            "only-test".to_string(),
            RulesetConfig {
                paths: PathConfig {
                    only: Some(vec!["test/**".to_string()]),
                    ignore: vec![],
                },
                rules: HashMap::from([(
                    "ignores-code".to_string(),
                    RuleConfig {
                        paths: PathConfig {
                            ignore: vec!["*/code/**".to_string()],
                            only: None,
                        },
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
        let config = HashMap::from([
            (
                "only-test-starstar-foo-glob".to_string(),
                RulesetConfig {
                    paths: PathConfig {
                        only: Some(vec!["test/**/foo.go".to_string()]),
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
                        ignore: vec!["uno/code".to_string()],
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
