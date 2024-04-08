// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::checker::CheckData;
use crate::matcher::PatternId;
use crate::Checker;
use std::sync::Arc;

/// A [`Checker`] that represents the boolean expression evaluation of other `Checker`s.
pub struct BooleanLogic(Arc<Expression>);

impl BooleanLogic {
    pub fn new(expr: Arc<Expression>) -> Self {
        Self(expr)
    }

    /// Constructs a depth 1 [`Expression::And`] with the passed in [`Checker`]s as the
    /// left-hand side and right-hand side.
    pub fn and(lhs: &Arc<dyn Checker>, rhs: &Arc<dyn Checker>) -> BooleanLogic {
        Self(Arc::from(Expression::And(
            Self::check(lhs).0,
            Self::check(rhs).0,
        )))
    }

    /// Constructs a depth 1 [`Expression::Or`] with the passed in [`Checker`]s as the
    /// left-hand side and right-hand side.
    pub fn or(lhs: &Arc<dyn Checker>, rhs: &Arc<dyn Checker>) -> BooleanLogic {
        Self(Arc::from(Expression::Or(
            Self::check(lhs).0,
            Self::check(rhs).0,
        )))
    }

    /// Constructs a depth 1 [`Expression::Not`] with the passed in [`Checker`] as the child.
    pub fn not(expr: &Arc<dyn Checker>) -> BooleanLogic {
        Self(Arc::from(Expression::Not(Self::check(expr).0)))
    }

    /// Constructs an `Expression` from the given [`Checker`]
    pub fn check(expr: &Arc<dyn Checker>) -> BooleanLogic {
        Self(Arc::from(Expression::Check(Arc::clone(expr))))
    }
}

impl Checker for BooleanLogic {
    fn check(&self, input: &CheckData) -> bool {
        evaluate(Arc::clone(&self.0), input)
    }
}

/// An expression for [`BooleanLogic`] supporting AND, OR, and NOT.
pub enum Expression {
    /// A [`Checker`]
    Check(Arc<dyn Checker>),
    /// Logical `AND`
    And(Arc<Expression>, Arc<Expression>),
    /// Logical `OR`
    Or(Arc<Expression>, Arc<Expression>),
    /// Logical `NOT`
    Not(Arc<Expression>),
}

/// Recursively evaluates the expression
fn evaluate(expr: Arc<Expression>, data: &CheckData) -> bool {
    match expr.as_ref() {
        Expression::Check(checker) => checker.check(data),
        Expression::And(lhs, rhs) => {
            evaluate(Arc::clone(lhs), data) && evaluate(Arc::clone(rhs), data)
        }
        Expression::Or(lhs, rhs) => {
            evaluate(Arc::clone(lhs), data) || evaluate(Arc::clone(rhs), data)
        }
        Expression::Not(expr) => !evaluate(Arc::clone(expr), data),
    }
}
