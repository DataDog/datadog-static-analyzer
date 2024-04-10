// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::check::Check;
use secrets_core::Checker;

/// A [`Checker`] that interprets the input as a [`String`] and checks if it matches any of the
/// specified input strings.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct AnyOf(Vec<String>);

impl AnyOf {
    pub fn new<T: ToString>(items: impl IntoIterator<Item = T>) -> Self {
        let strings = items
            .into_iter()
            .map(|item| item.to_string())
            .collect::<Vec<_>>();
        Self(strings)
    }
}

impl Checker for AnyOf {
    fn check(&self, input: &[u8]) -> bool {
        self.0.iter().any(|value| value.as_bytes() == input)
    }
}

impl From<AnyOf> for Check {
    fn from(value: AnyOf) -> Self {
        Self::AnyOf(value)
    }
}

/// A [`Checker`] that interprets the input as a [`String`] and checks for equality.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub(crate) struct Equals(String);

impl Equals {
    pub fn new<T: ToString>(item: T) -> Self {
        Self(item.to_string())
    }
}

impl Checker for Equals {
    fn check(&self, input: &[u8]) -> bool {
        self.0.as_bytes() == input
    }
}

impl From<Equals> for Check {
    fn from(value: Equals) -> Self {
        Self::Equals(value)
    }
}

/// A [`Checker`] that interprets the input as a [`String`] and returns true if the substring
/// is contained within the input string.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub(crate) struct Contains(String);

impl Contains {
    pub fn new<T: ToString>(item: T) -> Self {
        Self(item.to_string())
    }
}

impl Checker for Contains {
    /// Returns true if the underlying string slice is contained within the input bytes.
    ///
    /// # Panics
    /// Panics if the `input` is not valid UTF-8.
    fn check(&self, input: &[u8]) -> bool {
        let text = std::str::from_utf8(input).expect("input bytes should be valid utf-8");

        text.contains(self.0.as_str())
    }
}

impl From<Contains> for Check {
    fn from(value: Contains) -> Self {
        Self::Contains(value)
    }
}
