// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::check::Check;
use crate::proximity::{build_proximity_pattern, restore_rule_match_mut, PROXIMITY_MAGIC};
use crate::rule_file::matcher::RawMatcher;
use crate::rule_file::validator::http::RawExtension;
use crate::rule_file::validator::RawValidator;
use crate::rule_file::{
    parse_candidate_variable, CandidateVariable, RawMultiRuleFile, RawRuleFile,
};
use crate::validator::http;
use secrets_core::engine::{Engine, EngineBuilder, ValidationResult};
use secrets_core::matcher::hyperscan::HyperscanBuilder;
use secrets_core::matcher::{MatcherId, PatternId};
use secrets_core::rule::{RuleId, TargetedChecker};
use secrets_core::validator::http::RetryConfig;
use secrets_core::validator::{Candidate, ValidatorId};
use secrets_core::{Matcher, Rule, Validator};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::{fs, io};

#[derive(Debug, thiserror::Error)]
pub enum ScannerError {
    #[error("engine error: {message}")]
    Engine { message: String },
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub struct Scanner {
    rule_map: HashMap<String, RuleInfo>,
    engine: Engine,
}

impl Scanner {
    pub fn scan_file(&self, file_path: &Path) -> Result<Vec<Candidate>, ScannerError> {
        if self.rule_count() == 0 {
            return Ok(vec![]);
        }
        let file_contents = fs::read(file_path).map_err(ScannerError::Io)?;
        self.engine
            .scan(file_path, &file_contents)
            .map(|mut candidates| {
                for candidate in candidates.iter_mut() {
                    restore_rule_match_mut(&mut candidate.rule_match);
                }
                candidates
            })
            .map_err(|err| ScannerError::Engine {
                message: err.to_string(),
            })
    }

    pub fn validate_candidate(
        &self,
        candidate: &Candidate,
    ) -> Result<ValidationResult, ScannerError> {
        self.engine
            .validate_candidate(candidate.clone())
            .map_err(|err| ScannerError::Engine {
                message: err.to_string(),
            })
    }

    /// Returns information about a rule, if it exists
    pub fn rule(&self, id: &str) -> Option<&RuleInfo> {
        self.rule_map.get(id)
    }

    /// Returns all of the rules used by the scanner.
    pub fn rules(&self) -> impl IntoIterator<Item = &RuleInfo> {
        self.rule_map.values()
    }

    /// Returns the number of rules used by the scanner.
    pub fn rule_count(&self) -> usize {
        self.rule_map.len()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ScannerBuilderError {
    #[error("duplicate rule id: `{0}`")]
    DuplicateRuleId(String),
    #[error("error compiling rule `{rule}`: {message}")]
    RuleCompilationError { rule: String, message: String },
    #[error("{message}")]
    InvalidYamlSyntax { message: String },
    #[error("{0}")]
    CompilationError(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum RuleSource {
    /// A file containing multiple YAML-defined rules.
    YamlFileMultiRule(PathBuf),
    /// A file containing a single YAML-defined rule.
    YamlFile(PathBuf),
    /// A string that will be parsed as YAML.
    YamlLiteral(String),
}

/// A builder for a [`Scanner`].
#[derive(Default)]
pub struct ScannerBuilder {
    rule_sources: Vec<RuleSource>,
    /// `Rule` has a one-to-many relationship with `Pattern`
    rule_mapping: HashMap<RuleId, PatternId>,
    // ---
    // Validator-specific configuration
    http_retry: RetryConfig,
    // ---
    // Built items
    hs_builder: HyperscanBuilder,
    built_validators: Vec<Box<dyn Validator + Send + Sync>>,
    built_rules: Vec<Rule>,
    rule_infos: Vec<RuleInfo>,
}

impl ScannerBuilder {
    /// Instantiates a new builder for a [`Scanner`].
    pub fn new() -> Self {
        // (This ID is an arbitrary number, and is only hardcoded here because only one Matcher is currently used)
        let matcher_id = MatcherId(1);
        Self {
            rule_sources: Vec::new(),
            rule_mapping: HashMap::new(),
            http_retry: RetryConfig::default(),
            hs_builder: HyperscanBuilder::new(matcher_id),
            built_validators: Vec::new(),
            built_rules: Vec::new(),
            rule_infos: Vec::new(),
        }
    }

    /// Adds a file path to be read and parsed as a file containing multiple YAML-defined rules.
    pub fn yaml_file_multi_rule(mut self, file_path: impl Into<PathBuf>) -> Self {
        self.rule_sources
            .push(RuleSource::YamlFileMultiRule(file_path.into()));
        self
    }

    /// Adds a file path to be read and parsed as a YAML-defined rule.
    pub fn yaml_file(mut self, file_path: impl Into<PathBuf>) -> Self {
        self.rule_sources
            .push(RuleSource::YamlFile(file_path.into()));
        self
    }

    /// Adds a string containing YAML-defined rule.
    pub fn yaml_string(mut self, yaml_str: impl Into<String>) -> Self {
        self.rule_sources
            .push(RuleSource::YamlLiteral(yaml_str.into()));
        self
    }

    /// Configures the global retry settings for all [`HttpValidator`](http::HttpValidator)
    pub fn http_retry(mut self, config: &RetryConfig) -> Self {
        self.http_retry = config.clone();
        self
    }

    pub fn try_build(mut self) -> Result<Scanner, ScannerBuilderError> {
        let rule_sources = std::mem::take(&mut self.rule_sources);
        for rule_source in rule_sources {
            let raw_rules = Self::extract_raw_rules(rule_source)?;
            for raw in raw_rules {
                self.compile_rule_mut(raw)?;
            }
        }
        let hs = self
            .hs_builder
            .try_compile()
            .map_err(|err| ScannerBuilderError::CompilationError(err.to_string()))?;
        let engine = EngineBuilder::new()
            .matcher(Matcher::Hyperscan(hs))
            .validators(self.built_validators)
            .rules(self.built_rules)
            .build();
        let rule_map = self
            .rule_infos
            .into_iter()
            .map(|info| (info.rule_id.clone(), info))
            .collect::<HashMap<_, _>>();
        Ok(Scanner { engine, rule_map })
    }

    fn extract_raw_rules(rule_source: RuleSource) -> Result<Vec<RawRuleFile>, ScannerBuilderError> {
        enum Kind {
            Multi(String),
            Single(String),
        }

        let yaml_contents = match rule_source {
            RuleSource::YamlFile(path) => {
                Kind::Single(fs::read_to_string(path).map_err(ScannerBuilderError::Io)?)
            }
            RuleSource::YamlFileMultiRule(path) => {
                Kind::Multi(fs::read_to_string(path).map_err(ScannerBuilderError::Io)?)
            }
            RuleSource::YamlLiteral(literal) => Kind::Single(literal),
        };

        let raw_rules = match yaml_contents {
            Kind::Multi(contents) => {
                let raw = serde_yaml::from_str::<RawMultiRuleFile>(&contents).map_err(|err| {
                    ScannerBuilderError::InvalidYamlSyntax {
                        message: err.to_string(),
                    }
                })?;
                raw.0.into_values().collect::<Vec<_>>()
            }
            Kind::Single(contents) => {
                let raw = serde_yaml::from_str::<RawRuleFile>(&contents).map_err(|err| {
                    ScannerBuilderError::InvalidYamlSyntax {
                        message: err.to_string(),
                    }
                })?;
                vec![raw]
            }
        };
        Ok(raw_rules)
    }

    /// Compiles a rule, mutating all inner data as necessary.
    fn compile_rule_mut(&mut self, raw_rule: RawRuleFile) -> Result<(), ScannerBuilderError> {
        /// A transformation of the user's Hyperscan pattern.
        /// When we modify the user's Regex, we need to restore the original semantic so their `PatternMatch` logic
        /// and `Candidate` logic act as if our transformation never occurred in the first place.
        enum Transformation {
            Proximity,
            None,
        }

        let rule_id: RuleId = raw_rule.id.into();
        let entry = match self.rule_mapping.entry(rule_id.clone()) {
            Entry::Occupied(_) => {
                return Err(ScannerBuilderError::DuplicateRuleId(rule_id.to_string()));
            }
            Entry::Vacant(entry) => entry,
        };

        self.rule_infos.push(RuleInfo {
            rule_id: rule_id.to_string(),
            description: raw_rule.description.unwrap_or_default(),
            short_description: raw_rule.short_description.unwrap_or_default(),
        });

        let mut checks = Vec::new();
        let pattern_id = match raw_rule.matcher.deref() {
            RawMatcher::Hyperscan(raw) => {
                // Transform the user's regex, if needed
                let (pattern, transformation) = if let Some(proximity) = &raw.proximity {
                    const DEFAULT_MAX_DISTANCE: usize = 40;
                    let max_distance = proximity.max_distance.unwrap_or(DEFAULT_MAX_DISTANCE);
                    let proximity_keywords = proximity.keywords.iter().map(String::as_str);

                    let proximity_pattern =
                        build_proximity_pattern(&raw.pattern, proximity_keywords, max_distance)
                            .map_err(|err| ScannerBuilderError::RuleCompilationError {
                                rule: rule_id.to_string(),
                                message: err.to_string(),
                            })?;
                    (proximity_pattern, Transformation::Proximity)
                } else {
                    (raw.pattern.clone(), Transformation::None)
                };

                let pattern_id = self.hs_builder.add_regex(pattern).map_err(|err| {
                    ScannerBuilderError::RuleCompilationError {
                        rule: rule_id.to_string(),
                        message: err.to_string(),
                    }
                })?;
                entry.insert(pattern_id);

                // Convert the user input into a formatted `PatternCheck`
                if let Some(raw_checks) = &raw.checks {
                    for raw_check in raw_checks {
                        let check = Check::from_raw(raw_check);
                        let pattern_checker = match parse_candidate_variable(
                            raw_check.input_variable(),
                        ) {
                            None => {
                                return Err(ScannerBuilderError::RuleCompilationError { rule: rule_id.to_string(), message: format!("`{}` is not a valid variable: expecting either \"candidate\" or a capture name prepended by \"candidate.captures.\"", raw_check.input_variable()) });
                            }
                            Some(CandidateVariable::Entire) => {
                                match transformation {
                                    // If we transformed the user's regex into a Proximity pattern, whenever a
                                    // `PatternChecker` requests the entire candidate, we need to transparently
                                    // substitute what would've been the result of their unmodified pattern.
                                    Transformation::Proximity => {
                                        TargetedChecker::named_capture(PROXIMITY_MAGIC, check)
                                    }
                                    Transformation::None => TargetedChecker::candidate(check),
                                }
                            }
                            Some(CandidateVariable::Capture(name)) => {
                                TargetedChecker::named_capture(name, check)
                            }
                        };
                        checks.push(pattern_checker);
                    }
                }
                pattern_id
            }
        };

        let validator = match raw_rule.validator.deref() {
            RawValidator::Http(raw_http) => match &raw_http.0 {
                RawExtension::Simple(raw_cfg) => {
                    // Because it's derived from rule_id, this is a unique id.
                    let validator_id = ValidatorId::from(format!("validator-http_{}", rule_id));
                    http::build_simple_http(raw_cfg.clone(), validator_id, &self.http_retry)
                }
            },
        };

        let validator_id = validator.id().clone();
        let rule = Rule::new(rule_id, pattern_id, validator_id, Vec::new(), checks);
        self.built_rules.push(rule);

        let boxed: Box<dyn Validator + Send + Sync> = Box::new(validator);
        self.built_validators.push(boxed);

        Ok(())
    }
}

/// Metadata about a Rule that isn't related to its functionality
#[derive(Debug, Clone)]
pub struct RuleInfo {
    pub rule_id: String,
    pub description: String,
    pub short_description: String,
}

#[cfg(test)]
mod tests {
    use crate::scanner::ScannerBuilder;
    use httpmock::MockServer;
    use std::path::PathBuf;

    const RULE_FILE: &str = "\
schema-version: v1
id: rule-one
matcher:
  hyperscan:
    pattern: (?<org_id>[a-z]{3})_[[:xdigit:]]{8}
    checks:
      - any-of:
          input: ${{ candidate.captures.org_id }}
          values: ['abc', 'xyz']
validator:
  http:
    extension: simple-request
    config:
      request:
        url: <__cfg(test)_magic_url__>/?id=${{ candidate.captures.org_id }}
        method: GET
        headers:
          Authorization: Bearer ${{ candidate }}
      response-handler:
        handler-list:
        default-result:
          secret: INCONCLUSIVE
          severity: NOTICE
";

    /// Tests the proper construction of `Scanner`, from correct Matcher to correct Validator to correct Rule
    #[test]
    fn matcher_captures_exported() {
        let ms = MockServer::start();
        let mock = ms.mock(|when, then| {
            when.method("GET")
                .path("/")
                .query_param("id", "abc")
                .header("Authorization", "Bearer abc_018cf028");
            then.status(200);
        });
        let yaml = RULE_FILE.replace("<__cfg(test)_magic_url__>", &ms.base_url());
        let scanner = ScannerBuilder::new().yaml_string(yaml).try_build().unwrap();

        let file_contents = "--- abc_018cf028 ---";
        let candidates = scanner
            .engine
            .scan(&PathBuf::new(), file_contents.as_bytes())
            .unwrap();
        // We only need to check that the HTTP request was sent with the captures substituted, not the result.
        let _ = scanner.engine.validate_candidate(candidates[0].clone());
        mock.assert_hits(1);
    }
}
