// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::matcher::PatternMatch;
use crate::{Checker, PatternChecker};
use std::sync::Arc;

/// Builds a struct that implements boolean logic, given the passed in Trait that implements a `check`-like function.
macro_rules! boolean_logic {
    ($struct_name:ident, $enum_name:ident, $base_trait:ident, $input_type:ty) => {
        #[doc = concat!("A [`", stringify!($base_trait), "`] that represents the boolean expression evaluation of other `", stringify!($base_trait), "`s.")]
        pub struct $struct_name(Arc<$enum_name>);

        impl $struct_name {
            pub fn new(expr: Arc<$enum_name>) -> Self {
                Self(expr)
            }

            #[doc = "Recursively evaluates the expression"]
            fn evaluate(expr: Arc<$enum_name>, data: &$input_type) -> bool {
                match expr.as_ref() {
                    $enum_name::Check(checker) => checker.check(data),
                    $enum_name::And(lhs, rhs) => {
                        Self::evaluate(Arc::clone(lhs), data) && Self::evaluate(Arc::clone(rhs), data)
                    }
                    $enum_name::Or(lhs, rhs) => {
                        Self::evaluate(Arc::clone(lhs), data) || Self::evaluate(Arc::clone(rhs), data)
                    }
                    $enum_name::Not(expr) => !Self::evaluate(Arc::clone(expr), data),
                }
            }
        }

        impl $base_trait for $struct_name {
            fn check(&self, input: &$input_type) -> bool {
                Self::evaluate(Arc::clone(&self.0), input)
            }
        }

        #[doc = concat!("An expression for [`", stringify!($struct_name), "`] supporting AND, OR, and NOT.")]
        pub enum $enum_name {
            /// A [`Checker`]
            Check(Arc<Box<dyn $base_trait>>),
            /// Logical `AND`
            And(Arc<$enum_name>, Arc<$enum_name>),
            /// Logical `OR`
            Or(Arc<$enum_name>, Arc<$enum_name>),
            /// Logical `NOT`
            Not(Arc<$enum_name>),
        }

        impl $enum_name {
            #[doc = concat!("Constructs a [`", stringify!($enum_name), "::And`] with the passed in [`", stringify!($base_trait), "`]s as the left-hand side and right-hand side.")]
            pub fn and(lhs: &Arc<$enum_name>, rhs:  &Arc<$enum_name>) -> Arc<$enum_name> {
                Arc::new($enum_name::And(Arc::clone(lhs), Arc::clone(rhs)))
            }

            #[doc = concat!("Constructs a [`", stringify!($enum_name), "::Or`] with the passed in [`", stringify!($base_trait), "`]s as the left-hand side and right-hand side.")]
            pub fn or(lhs: &Arc<$enum_name>, rhs:  &Arc<$enum_name>) -> Arc<$enum_name> {
                Arc::new($enum_name::Or(Arc::clone(lhs), Arc::clone(rhs)))
            }

            #[doc = concat!("Constructs a [`", stringify!($enum_name), "::Not`] with the passed in [`", stringify!($base_trait), "`] as the child.")]
            pub fn not(expr: &Arc<$enum_name>) -> Arc<$enum_name> {
                Arc::new($enum_name::Not(Arc::clone(expr)))
            }

            #[doc = concat!("Constructs an `Expression` from the given [`", stringify!($base_trait), "`].")]
            pub fn check<T: $base_trait + 'static>(expr: T) -> Arc<$enum_name> {
                let expr: Box<dyn $base_trait> = Box::new(expr);
                Arc::new($enum_name::Check(Arc::new(expr)))
            }
        }
    };
}

boolean_logic!(BooleanLogic, Expression, Checker, [u8]);
boolean_logic!(PmBooleanLogic, PmExpression, PatternChecker, PatternMatch);

#[cfg(test)]
mod tests {
    use crate::checker::boolean_logic::Expression;
    use crate::checker::{BooleanLogic, Regex};
    use crate::Checker;
    use std::sync::Arc;

    #[test]
    fn boolean_logic() {
        let starts_with_letter = Expression::check(Regex::try_new("^[[:alpha:]]").unwrap());
        let ends_with_letter = Expression::check(Regex::try_new("[[:alpha:]]$").unwrap());

        let starts_with_digit = Expression::check(Regex::try_new("^[[:digit:]]").unwrap());
        let ends_with_digit = Expression::check(Regex::try_new("[[:digit:]]$").unwrap());

        // (starts_with_letter && ends_with_digit) || (starts_with_digit && ends_with_letter)
        let first_and = Expression::and(&starts_with_letter, &ends_with_digit);
        let second_and = Expression::and(&starts_with_digit, &ends_with_letter);
        let expression = Expression::or(&first_and, &second_and);

        let bool_logic = BooleanLogic::new(Arc::clone(&expression));

        assert!(bool_logic.check(b"a---1"));
        assert!(bool_logic.check(b"1---a"));
        assert!(!bool_logic.check(b"a---a"));
        assert!(!bool_logic.check(b"1---1"));

        let starts_with_1 = Expression::check(Regex::try_new("^1").unwrap());
        let not_starts_with_1 = Expression::not(&starts_with_1);

        let new_expression = Expression::and(&expression, &not_starts_with_1);
        let bool_logic = BooleanLogic::new(new_expression);

        assert!(bool_logic.check(b"a---1"));
        assert!(!bool_logic.check(b"1---a"));
        assert!(bool_logic.check(b"2---a"));
    }
}
