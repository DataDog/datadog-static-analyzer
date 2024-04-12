// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::location::PointLocator;
use crate::rule::{Rule, RuleId, RuleMatch};
use crate::rule_evaluator::{EvaluatorError, RuleEvaluator};
use crate::validator::Candidate;
use crate::Matcher;
use std::path::Path;
use std::string::FromUtf8Error;
use std::sync::Arc;

pub struct Worker {
    rules: Vec<RuleId>,
    rule_evaluator: RuleEvaluator,
}

#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Utf8(#[from] FromUtf8Error),
    #[error("rule evaluator error: {0}")]
    Evaluator(#[from] EvaluatorError),
}

impl Worker {
    pub fn new(matchers: impl Into<Vec<Matcher>>, rules: impl AsRef<[Arc<Rule>]>) -> Self {
        let rule_ids = rules
            .as_ref()
            .iter()
            .map(|rule| rule.id().clone())
            .collect::<Vec<_>>();
        let rule_evaluator = RuleEvaluator::new(matchers, rules);
        Self {
            rules: rule_ids,
            rule_evaluator,
        }
    }

    /// Scans the given bytes with every rule the worker implements.
    pub fn scan(&mut self, path: &Path, data: &[u8]) -> Result<Vec<Candidate>, WorkerError> {
        let locator = PointLocator::new(data);
        let mut candidates = Vec::new();
        let scanner = self.rule_evaluator.scan(data);

        for rule_id in &self.rules {
            let scan_iter = scanner.rule(rule_id).map_err(WorkerError::Evaluator)?;
            for checked_match in scan_iter {
                let (matched, captures) = checked_match
                    .try_into_owned_components(&locator)
                    .map_err(WorkerError::Utf8)?;
                let candidate = Candidate {
                    source: path.to_path_buf(),
                    rule_match: RuleMatch {
                        rule_id: rule_id.clone(),
                        matched,
                        captures,
                    },
                };
                candidates.push(candidate);
            }
        }
        Ok(candidates)
    }
}
