use crate::file_utils::is_allowed_by_path_config;
use crate::model::config_file::{ConfigFile, PathConfig};
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
    /// Builds a PathRestrictions from a configuration file.
    pub fn from_config(cfg: &ConfigFile) -> PathRestrictions {
        let mut out = PathRestrictions::default();
        for (name, ruleset_config) in &cfg.rulesets {
            let mut restriction = RestrictionsForRuleset {
                paths: ruleset_config.paths.clone(),
                ..Default::default()
            };
            if let Some(rules) = &ruleset_config.rules {
                for (name, rule_config) in rules {
                    restriction
                        .rules
                        .insert(name.clone(), rule_config.paths.clone());
                }
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
        let (ruleset, short_name) = rule_name.split_once('/').unwrap();
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

#[cfg(test)]
mod tests {
    use crate::model::config_file::{ConfigFile, PathConfig, RuleConfig, RulesetConfig};
    use crate::path_restrictions::PathRestrictions;
    use std::collections::HashMap;

    // By default, everything is included.
    #[test]
    fn empty_restrictions() {
        let config_file = ConfigFile {
            rulesets: HashMap::from([("go-security".to_string(), RulesetConfig::default())]),
            ..Default::default()
        };
        let path_restrictions = PathRestrictions::from_config(&config_file);
        let mut filter = path_restrictions.get_filter_for_file("src/main.go");
        assert!(filter.rule_is_included("go-security/is-included"));
        assert!(filter.rule_is_included("any-ruleset/is-included"));
    }

    // Can include and exclude rulesets.
    #[test]
    fn ruleset_restrictions() {
        let config_file = ConfigFile {
            rulesets: HashMap::from([
                (
                    "go-security".to_string(),
                    RulesetConfig {
                        paths: PathConfig {
                            ignore: Some(vec!["test/**".to_string()]),
                            only: None,
                        },
                        ..Default::default()
                    },
                ),
                (
                    "go-best-practices".to_string(),
                    RulesetConfig {
                        paths: PathConfig {
                            ignore: None,
                            only: Some(vec!["*/code/**".to_string()]),
                        },
                        ..Default::default()
                    },
                ),
            ]),
            ..Default::default()
        };
        let path_restrictions = PathRestrictions::from_config(&config_file);
        let mut filter = path_restrictions.get_filter_for_file("test/main.go");
        assert!(!filter.rule_is_included("go-security/anything"));
        assert!(!filter.rule_is_included("go-best-practices/any-other-thing"));
        assert!(filter.rule_is_included("any-other-ruleset/anything-at-all"));
        let mut filter = path_restrictions.get_filter_for_file("uno/code/proto.go");
        assert!(filter.rule_is_included("go-security/anything"));
        assert!(filter.rule_is_included("go-best-practices/any-other-thing"));
        assert!(filter.rule_is_included("any-other-ruleset/anything-at-all"));
    }

    // Can include and exclude individual rules.
    #[test]
    fn rule_restrictions() {
        let config_file = ConfigFile {
            rulesets: HashMap::from([
                (
                    "go-security".to_string(),
                    RulesetConfig {
                        paths: PathConfig::default(),
                        rules: Some(HashMap::from([(
                            "nil-deref".to_string(),
                            RuleConfig {
                                paths: PathConfig {
                                    ignore: Some(vec!["test/**".to_string()]),
                                    only: None,
                                },
                            },
                        )])),
                        ..Default::default()
                    },
                ),
                (
                    "go-best-practices".to_string(),
                    RulesetConfig {
                        paths: PathConfig::default(),
                        rules: Some(HashMap::from([(
                            "use-gofmt".to_string(),
                            RuleConfig {
                                paths: PathConfig {
                                    ignore: None,
                                    only: Some(vec!["*/code/**".to_string()]),
                                },
                            },
                        )])),
                        ..Default::default()
                    },
                ),
            ]),
            ..Default::default()
        };
        let path_restrictions = PathRestrictions::from_config(&config_file);
        let mut filter = path_restrictions.get_filter_for_file("test/main.go");
        assert!(!filter.rule_is_included("go-security/nil-deref"));
        assert!(filter.rule_is_included("go-security/other-rule"));
        assert!(!filter.rule_is_included("go-best-practices/use-gofmt"));
        assert!(filter.rule_is_included("go-best-practices/other-rule"));
        let mut filter = path_restrictions.get_filter_for_file("uno/code/proto.go");
        assert!(filter.rule_is_included("go-security/nil-deref"));
        assert!(filter.rule_is_included("go-security/other-rule"));
        assert!(filter.rule_is_included("go-best-practices/use-gofmt"));
        assert!(filter.rule_is_included("go-best-practices/other-rule"));
    }

    // Can combine inclusion and exclusions for rules and rulesets.
    #[test]
    fn ruleset_and_rule_restrictions() {
        let config_file = ConfigFile {
            rulesets: HashMap::from([(
                "go-security".to_string(),
                RulesetConfig {
                    paths: PathConfig {
                        only: Some(vec!["test/**".to_string()]),
                        ignore: None,
                    },
                    rules: Some(HashMap::from([(
                        "nil-deref".to_string(),
                        RuleConfig {
                            paths: PathConfig {
                                ignore: Some(vec!["test/main.go".to_string()]),
                                only: None,
                            },
                        },
                    )])),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        let path_restrictions = PathRestrictions::from_config(&config_file);
        let mut filter = path_restrictions.get_filter_for_file("test/main.go");
        assert!(!filter.rule_is_included("go-security/nil-deref"));
        assert!(filter.rule_is_included("go-security/other-rule"));
        let mut filter = path_restrictions.get_filter_for_file("test/not_main.go");
        assert!(filter.rule_is_included("go-security/nil-deref"));
        assert!(filter.rule_is_included("go-security/other-rule"));
    }

    // Can do prefix and glob pattern matching.
    #[test]
    fn prefix_and_glob_matching() {
        let config_file = ConfigFile {
            rulesets: HashMap::from([
                (
                    "go-security".to_string(),
                    RulesetConfig {
                        paths: PathConfig {
                            only: Some(vec!["test/**/foo.go".to_string()]),
                            ignore: None,
                        },
                        ..Default::default()
                    },
                ),
                (
                    "go-best-practices".to_string(),
                    RulesetConfig {
                        paths: PathConfig {
                            only: None,
                            ignore: Some(vec!["uno/code".to_string()]),
                        },
                        ..Default::default()
                    },
                ),
            ]),
            ..Default::default()
        };
        let path_restrictions = PathRestrictions::from_config(&config_file);
        let mut filter = path_restrictions.get_filter_for_file("test/main.go");
        assert!(!filter.rule_is_included("go-security/anything"));
        let mut filter = path_restrictions.get_filter_for_file("test/main/foo.go");
        assert!(filter.rule_is_included("go-security/anything"));
        let mut filter = path_restrictions.get_filter_for_file("uno/code/proto.go");
        assert!(!filter.rule_is_included("go-best-practices/anything"));
        let mut filter = path_restrictions.get_filter_for_file("uno/proto.go");
        assert!(filter.rule_is_included("go-best-practices/anything"));
    }
}
