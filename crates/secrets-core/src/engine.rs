// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::common::ByteSpan;
use crate::location::PointSpan;
use crate::matcher::Matcher;
use crate::rule::{Rule, RuleId};
use crate::validator::{Candidate, SecretCategory, Validator};
use crate::worker::{Worker, WorkerError};
use std::cell::RefCell;
use std::io;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Worker(#[from] WorkerError),
}

pub struct Engine {
    rules: Vec<Rule>,
    matchers: Vec<Matcher>,
    validators: Vec<Arc<Mutex<Box<dyn Validator + Send + Sync>>>>,
    run_validation: bool,
}

thread_local! {
    static WORKER: RefCell<Option<Worker>> = const { RefCell::new(None) };
}
impl Engine {
    pub fn scan_file(&self, file_path: &Path) -> Result<Vec<Candidate>, EngineError> {
        WORKER.with(|ref_cell| {
            let mut ref_mut = ref_cell.borrow_mut();
            if ref_mut.is_none() {
                *ref_mut = Some(self.init_worker());
            }
            let worker = ref_mut
                .as_mut()
                .expect("worker should have been initialized");

            worker.analyze_file(file_path).map_err(EngineError::Worker)
        })
    }

    fn validate_candidate(&self, _candidate: Candidate) -> Result<ValidationResult, EngineError> {
        todo!()
    }

    /// Creates a new Worker. This should be considered an expensive operation, as it will create a
    /// new instance of each Matcher and initialize it, which may have significant overhead.
    fn init_worker(&self) -> Worker {
        let rules = self
            .rules
            .iter()
            .map(|rule| Arc::new(rule.clone()))
            .collect::<Vec<_>>();
        let matchers = self.matchers.clone();
        Worker::new(matchers, rules)
    }
}

pub struct EngineBuilder {
    rules: Vec<Rule>,
    matchers: Vec<Matcher>,
    validators: Vec<Box<dyn Validator + Send + Sync>>,
    run_validation: bool,
}

impl EngineBuilder {
    pub fn new() -> EngineBuilder {
        Self {
            rules: Vec::new(),
            matchers: Vec::new(),
            validators: Vec::new(),
            run_validation: false,
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

    pub fn matcher(mut self, matcher: Matcher) -> Self {
        self.matchers.push(matcher);
        self
    }

    pub fn matchers(mut self, matchers: impl IntoIterator<Item = Matcher>) -> Self {
        self.matchers.extend(matchers);
        self
    }

    pub fn validation(mut self, enable: bool) -> Self {
        self.run_validation = enable;
        self
    }

    pub fn build(self) -> Engine {
        let validators = self
            .validators
            .into_iter()
            .map(|validator| Arc::new(Mutex::new(validator)))
            .collect::<Vec<_>>();
        Engine {
            rules: self.rules,
            matchers: self.matchers,
            validators,
            run_validation: self.run_validation,
        }
    }
}

impl Default for EngineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ValidationResult {
    rule_id: RuleId,
    category: SecretCategory,
    source: PathBuf,
    byte_span: ByteSpan,
    point_span: PointSpan,
}
