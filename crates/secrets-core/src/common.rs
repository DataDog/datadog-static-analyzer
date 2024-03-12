// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use vectorscan::HsMatch;

/// A span of bytes with an inclusive `start_index` and an exclusive `end_index`.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash)]
pub struct ByteSpan {
    pub start_index: u32,
    pub end_index: u32,
}

impl ByteSpan {
    /// Creates a ByteSpan given a start and end index.
    pub fn new(start_index: usize, end_index: usize) -> Self {
        Self {
            start_index: start_index as u32,
            end_index: end_index as u32,
        }
    }

    /// Returns a [`ByteSpan`] representing an entire slice.
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self {
            start_index: 0_u32,
            end_index: bytes.len() as u32,
        }
    }

    /// Returns the ByteSpan as a Range
    #[inline]
    pub fn as_range(&self) -> std::ops::Range<usize> {
        std::ops::Range {
            start: self.start_index as usize,
            end: self.end_index as usize,
        }
    }

    /// Returns the length represented by the ByteSpan
    #[allow(clippy::len_without_is_empty)]
    #[inline]
    pub fn len(&self) -> usize {
        debug_assert!(self.end_index >= self.start_index);
        (self.end_index - self.start_index) as usize
    }
}

impl From<HsMatch> for ByteSpan {
    fn from(value: HsMatch) -> Self {
        // We can downcast to u32 safely because Hyperscan itself can't scan over u32 bytes
        Self {
            start_index: value.start() as u32,
            end_index: value.end() as u32,
        }
    }
}

impl From<&HsMatch> for ByteSpan {
    fn from(value: &HsMatch) -> Self {
        Self::from(*value)
    }
}
