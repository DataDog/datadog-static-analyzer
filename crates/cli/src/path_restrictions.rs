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
                    restriction.rules.insert(name.clone(), rule_config.clone());
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
