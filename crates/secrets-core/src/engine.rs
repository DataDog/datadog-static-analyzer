// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::common::ByteSpan;
use crate::location::PointSpan;
use crate::matcher::{Matcher, MatcherId};
use crate::rule::{Rule, RuleId};
use crate::validator::{Candidate, SecretCategory, Validator, ValidatorError, ValidatorId};
use crate::worker::{Worker, WorkerError};
use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("unknown validator `{0}`")]
    UnknownValidator(String),
    #[error("unknown rule `{0}`")]
    UnknownRule(String),
    #[error(transparent)]
    Validator(#[from] ValidatorError),
    #[error(transparent)]
    Worker(#[from] WorkerError),
}

pub struct Engine {
    rules: HashMap<RuleId, Arc<Rule>>,
    matchers: HashMap<MatcherId, Matcher>,
    // Whereas `Rule` and `Matcher` are intended to be thread-local, a validator must be held
    // in an Arc because it may need to respect a rate-limit across threads.
    validators: HashMap<ValidatorId, Arc<dyn Validator + Send + Sync>>,
}

thread_local! {
    static WORKER: RefCell<Option<Worker>> = const { RefCell::new(None) };
}
impl Engine {
    /// Scans the `file_contents` against every rule.
    ///
    /// NOTE: No I/O is performed -- `path` is only used for metadata.
    pub fn scan(&self, path: &Path, file_contents: &[u8]) -> Result<Vec<Candidate>, EngineError> {
        WORKER.with(|ref_cell| {
            let mut ref_mut = ref_cell.borrow_mut();
            if ref_mut.is_none() {
                *ref_mut = Some(self.init_worker());
            }
            let worker = ref_mut
                .as_mut()
                .expect("worker should have been initialized");

            worker
                .scan(path, file_contents)
                .map_err(EngineError::Worker)
        })
    }

    pub fn validate_candidate(
        &self,
        candidate: Candidate,
    ) -> Result<ValidationResult, EngineError> {
        let rule_id = &candidate.rule_match.rule_id;
        let rule = self
            .rules
            .get(rule_id)
            .ok_or_else(|| EngineError::UnknownRule(rule_id.to_string()))?;
        let validator = self
            .validators
            .get(rule.validator_id())
            .ok_or_else(|| EngineError::UnknownValidator(rule.validator_id().to_string()))?;

        let source = candidate.source.clone();
        let byte_span = candidate.rule_match.matched.byte_span;
        let point_span = candidate.rule_match.matched.point_span;
        let rule_id = rule_id.clone();
        validator
            .validate(candidate)
            .map(|category| ValidationResult {
                rule_id,
                category,
                source,
                byte_span,
                point_span,
            })
            .map_err(EngineError::Validator)
    }

    /// Creates a new Worker. This should be considered an expensive operation, as it will create a
    /// new instance of each Matcher and initialize it, which may have significant overhead.
    fn init_worker(&self) -> Worker {
        let rules = self.rules.values().map(Arc::clone).collect::<Vec<_>>();

        // NOTE: This should be assumed to be expensive
        let matchers = self.matchers.values().cloned().collect::<Vec<_>>();

        Worker::new(matchers, rules)
    }
}

pub struct EngineBuilder {
    rules: Vec<Rule>,
    matchers: Vec<Matcher>,
    validators: Vec<Box<dyn Validator + Send + Sync>>,
}

impl EngineBuilder {
    pub fn new() -> EngineBuilder {
        Self {
            rules: Vec::new(),
            matchers: Vec::new(),
            validators: Vec::new(),
        }
    }

    pub fn rule(mut self, rule: Rule) -> Self {
        self.rules.push(rule);
        self
    }

    pub fn rules(mut self, rules: impl IntoIterator<Item = Rule>) -> Self {
        self.rules.extend(rules);
        self
    }

    pub fn validator(mut self, validator: Box<dyn Validator + Send + Sync>) -> Self {
        self.validators.push(validator);
        self
    }

    pub fn validators(
        mut self,
        validators: impl IntoIterator<Item = Box<dyn Validator + Send + Sync>>,
    ) -> Self {
        self.validators.extend(validators);
        self
    }

    pub fn matcher(mut self, matcher: Matcher) -> Self {
        self.matchers.push(matcher);
        self
    }

    pub fn matchers(mut self, matchers: impl IntoIterator<Item = Matcher>) -> Self {
        self.matchers.extend(matchers);
        self
    }

    pub fn build(self) -> Engine {
        let validators = self
            .validators
            .into_iter()
            .map(|validator| (validator.id().clone(), Arc::from(validator)))
            .collect::<HashMap<_, _>>();
        let matchers = self
            .matchers
            .into_iter()
            .map(|matcher| (matcher.id(), matcher))
            .collect::<HashMap<_, _>>();
        let rules = self
            .rules
            .into_iter()
            .map(|rule| (rule.id().clone(), Arc::from(rule)))
            .collect::<HashMap<_, _>>();
        Engine {
            rules,
            matchers,
            validators,
        }
    }
}

impl Default for EngineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A successful secret validation result, as well as its location within the source file.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    rule_id: RuleId,
    category: SecretCategory,
    source: PathBuf,
    byte_span: ByteSpan,
    point_span: PointSpan,
}

impl ValidationResult {
    pub fn rule_id(&self) -> &RuleId {
        &self.rule_id
    }

    pub fn category(&self) -> SecretCategory {
        self.category
    }

    pub fn source(&self) -> &Path {
        self.source.as_path()
    }

    pub fn byte_span(&self) -> ByteSpan {
        self.byte_span
    }

    pub fn point_span(&self) -> PointSpan {
        self.point_span
    }
}
