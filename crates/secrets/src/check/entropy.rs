// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::check::Check;
use secrets_core::Checker;

/// A [`Checker`] that interprets the input as a [`String`] and measures its Shannon entropy,
/// normalizing it to a given base.
///
/// Reference: https://en.wikipedia.org/wiki/Entropy_(information_theory)
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct NormalizedEntropy {
    /// A number between 0 and 1. When the normalized entropy is over this number, the check will return true.
    threshold: f32,
    /// The base to use to normalize the calculated entropy.
    base: u8,
}

impl NormalizedEntropy {
    /// Creates a new [`NormalizedEntropy`]. If no `base` is provided, 95 (the number of printable characters
    /// will be used).
    pub fn new(threshold: f32, base: Option<u8>) -> Self {
        let base = base.unwrap_or(95);
        Self { threshold, base }
    }

    fn normalized_entropy(&self, data: impl IntoIterator<Item = char>) -> f32 {
        let entropy = shannon_entropy(data);
        (entropy / (self.base as f32).log2()).clamp(0.0, 1.0)
    }
}

impl Checker for NormalizedEntropy {
    fn check(&self, input: &[u8]) -> bool {
        let normalized = self.normalized_entropy(String::from_utf8_lossy(input).chars());
        normalized >= self.threshold
    }
}

impl From<NormalizedEntropy> for Check {
    fn from(value: NormalizedEntropy) -> Self {
        Self::Entropy(value)
    }
}

fn shannon_entropy(data: impl IntoIterator<Item = char>) -> f32 {
    let mut data_len = 0_usize;
    let mut entropy = 0.0;
    let mut counts = [0_usize; 256];

    for ch in data.into_iter() {
        counts[ch as usize] += 1;
        data_len += 1;
    }

    for count in counts.into_iter().filter(|&count| count > 0) {
        let p = (count as f32) / (data_len as f32);
        entropy -= p * p.log2()
    }
    entropy
}

#[cfg(test)]
mod tests {
    use crate::check::entropy::NormalizedEntropy;

    #[test]
    fn entropy_zero() {
        let norm_entropy = NormalizedEntropy::new(0.5, Some(16));
        let str = "aaaaaaaa";
        assert_eq!(norm_entropy.normalized_entropy(str.chars()), 0.0);
    }

    #[test]
    fn entropy_default_base() {
        let str = "5f375a86";
        let norm_entropy = NormalizedEntropy::new(0.2, None);
        assert_eq!(norm_entropy.normalized_entropy(str.chars()), 0.41857845);
        let norm_entropy = NormalizedEntropy::new(0.2, Some(16));
        assert_eq!(norm_entropy.normalized_entropy(str.chars()), 0.6875);
    }

    #[test]
    fn entropy_clamped() {
        let str = "5f375a86";
        let norm_entropy = NormalizedEntropy::new(0.2, Some(1));
        assert_eq!(norm_entropy.normalized_entropy(str.chars()), 1.0);
    }
}
