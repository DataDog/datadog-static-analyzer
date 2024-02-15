use crate::file_utils::is_allowed_by_path_config;
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
    pub fn from_ruleset_configs(rulesets: &HashMap<String, RulesetConfig>) -> PathRestrictions {
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

    /// Returns a RuleFilter for the given path.
    pub fn get_filter_for_file(&self, file_path: &str) -> RuleFilter {
        RuleFilter {
            restrictions: self,
            file_path: file_path.to_string(),
            known_rulesets: HashMap::new(),
        }
    }
}

/// An object that provides a function to check if a rule applies to a predetermined file.
pub struct RuleFilter<'a> {
    /// The restrictions that apply.
    restrictions: &'a PathRestrictions,
    /// The path of the file to check.
    file_path: String,
    /// A cache of results for particular rulesets.
    ///
    /// Since one ruleset contains multiple alerts, this cache prevents checking the conditions
    /// for the same ruleset repeatedly.
    known_rulesets: HashMap<String, Known>,
}

/// Result for a ruleset.
#[derive(PartialEq, Clone)]
enum Known {
    /// The file passes this ruleset's restrictions.
    Included,
    /// The file does not pass this ruleset's restrictions.
    Excluded,
    /// The result depends on the particular rule.
    Depends,
}

impl<'a> RuleFilter<'a> {
    /// Returns whether the given rule applies to the file.
    pub fn rule_is_included(&mut self, rule_name: &str) -> bool {
        let (ruleset, short_name) = split_rule_name(rule_name);
        let known = match self.known_rulesets.get(ruleset) {
            Some(known) => known.clone(),
            None => match self.restrictions.rulesets.get(ruleset) {
                None => Known::Included,
                Some(restrictions) => {
                    let known = if !is_allowed_by_path_config(&restrictions.paths, &self.file_path)
                    {
                        Known::Excluded
                    } else if restrictions.rules.is_empty() {
                        Known::Included
                    } else {
                        Known::Depends
                    };
                    self.known_rulesets
                        .insert(ruleset.to_string(), known.clone());
                    known
                }
            },
        };
        if known != Known::Depends {
            return known == Known::Included;
        }
        match self
            .restrictions
            .rulesets
            .get(ruleset)
            .unwrap()
            .rules
            .get(short_name)
        {
            None => true,
            Some(paths) => is_allowed_by_path_config(paths, &self.file_path),
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
        let path_restrictions = PathRestrictions::from_ruleset_configs(&config);
        let mut filter = path_restrictions.get_filter_for_file("src/main.go");
        assert!(filter.rule_is_included("defined-ruleset/any-rule"));
        assert!(filter.rule_is_included("other-ruleset/any-rule"));
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
        let path_restrictions = PathRestrictions::from_ruleset_configs(&config);
        let mut filter = path_restrictions.get_filter_for_file("test/main.go");
        assert!(!filter.rule_is_included("ignores-test/any-rule"));
        assert!(!filter.rule_is_included("only-code/any-rule"));
        assert!(filter.rule_is_included("test-but-not-code/any-rule"));
        assert!(filter.rule_is_included("any-ruleset/any-rule"));
        let mut filter = path_restrictions.get_filter_for_file("uno/code/proto.go");
        assert!(filter.rule_is_included("ignores-test/any-rule"));
        assert!(filter.rule_is_included("only-code/any-rule"));
        assert!(!filter.rule_is_included("test-but-not-code/any-rule"));
        assert!(filter.rule_is_included("any-ruleset/any-rule"));
        let mut filter = path_restrictions.get_filter_for_file("test/code/proto_test.go");
        assert!(!filter.rule_is_included("ignores-test/any-rule"));
        assert!(filter.rule_is_included("only-code/any-rule"));
        assert!(!filter.rule_is_included("test-but-not-code/any-rule"));
        assert!(filter.rule_is_included("any-ruleset/any-rule"));
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
        let path_restrictions = PathRestrictions::from_ruleset_configs(&config);
        let mut filter = path_restrictions.get_filter_for_file("test/main.go");
        assert!(!filter.rule_is_included("a-ruleset/ignores-test"));
        assert!(!filter.rule_is_included("a-ruleset/only-code"));
        assert!(filter.rule_is_included("a-ruleset/test-but-not-code"));
        assert!(filter.rule_is_included("a-ruleset/any-ruleset"));
        let mut filter = path_restrictions.get_filter_for_file("uno/code/proto.go");
        assert!(filter.rule_is_included("a-ruleset/ignores-test"));
        assert!(filter.rule_is_included("a-ruleset/only-code"));
        assert!(!filter.rule_is_included("a-ruleset/test-but-not-code"));
        assert!(filter.rule_is_included("a-ruleset/any-ruleset"));
        let mut filter = path_restrictions.get_filter_for_file("test/code/proto_test.go");
        assert!(!filter.rule_is_included("a-ruleset/ignores-test"));
        assert!(filter.rule_is_included("a-ruleset/only-code"));
        assert!(!filter.rule_is_included("a-ruleset/test-but-not-code"));
        assert!(filter.rule_is_included("a-ruleset/any-ruleset"));
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
        let path_restrictions = PathRestrictions::from_ruleset_configs(&config);
        let mut filter = path_restrictions.get_filter_for_file("test/main.go");
        assert!(filter.rule_is_included("only-test/ignores-code"));
        assert!(filter.rule_is_included("only-test/any-rule"));
        assert!(filter.rule_is_included("any-ruleset/ignores-code"));
        assert!(filter.rule_is_included("any-ruleset/any-rule"));
        let mut filter = path_restrictions.get_filter_for_file("test/code/proto_test.go");
        assert!(!filter.rule_is_included("only-test/ignores-code"));
        assert!(filter.rule_is_included("only-test/any-rule"));
        assert!(filter.rule_is_included("any-ruleset/ignores-code"));
        assert!(filter.rule_is_included("any-ruleset/any-rule"));
        let mut filter = path_restrictions.get_filter_for_file("foo/code/main.go");
        assert!(!filter.rule_is_included("only-test/ignores-code"));
        assert!(!filter.rule_is_included("only-test/any-rule"));
        assert!(filter.rule_is_included("any-ruleset/ignores-code"));
        assert!(filter.rule_is_included("any-ruleset/any-rule"));
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
        let path_restrictions = PathRestrictions::from_ruleset_configs(&config);
        let mut filter = path_restrictions.get_filter_for_file("test/main.go");
        assert!(!filter.rule_is_included("only-test-starstar-foo-glob/rule"));
        assert!(filter.rule_is_included("ignore-uno-code-prefix/rule"));
        let mut filter = path_restrictions.get_filter_for_file("test/main/foo.go");
        assert!(filter.rule_is_included("only-test-starstar-foo-glob/rule"));
        assert!(filter.rule_is_included("ignore-uno-code-prefix/rule"));
        let mut filter = path_restrictions.get_filter_for_file("uno/code/proto.go");
        assert!(!filter.rule_is_included("only-test-starstar-foo-glob/rule"));
        assert!(!filter.rule_is_included("ignore-uno-code-prefix/rule"));
        let mut filter = path_restrictions.get_filter_for_file("uno/proto.go");
        assert!(!filter.rule_is_included("only-test-starstar-foo-glob/rule"));
        assert!(filter.rule_is_included("ignore-uno-code-prefix/rule"));
    }
}
