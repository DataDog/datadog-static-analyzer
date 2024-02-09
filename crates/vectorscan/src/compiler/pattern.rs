// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::common::TryToCString;
use crate::compiler::error::HsCompileError;
use crate::error::{check_ffi_result, Error};
use bitflags::bitflags;
use core::ffi;
use vectorscan_sys::hs;

bitflags! {
    /// Flags that modify the behavior of a [`Pattern`]. Multiple flags may be used by ORing them together.
    #[derive(Debug, Default, Copy, Clone, PartialEq, Eq, Hash)]
    pub struct Flags: u32 {
        /// Matching will be performed case-insensitively.
        const CASELESS = hs::HS_FLAG_CASELESS;
        /// Matching a `.` will not exclude newlines.
        const DOTALL = hs::HS_FLAG_DOTALL;
        /// `^` and `$` anchors match any newlines in data.
        const MULTI_LINE = hs::HS_FLAG_MULTILINE;
        /// Only one match will be generated for the pattern per stream.
        const SINGLE_MATCH = hs::HS_FLAG_SINGLEMATCH;
        /// Allow patterns which can match against an empty string, such as `.*`.
        const ALLOW_EMPTY = hs::HS_FLAG_ALLOWEMPTY;
        /// Treat this pattern as a sequence of UTF-8 characters.
        const UTF8 = hs::HS_FLAG_UTF8;
        /// Use Unicode properties for character classes.
        const UCP = hs::HS_FLAG_UCP;
        /// Compile pattern in prefiltering mode.
        const PREFILTER = hs::HS_FLAG_PREFILTER;
        /// Report the leftmost start of match offset when a match is found.
        const SOM_LEFTMOST = hs::HS_FLAG_SOM_LEFTMOST;
        /// Parse the pattern in [logical combination syntax](https://intel.github.io/hyperscan/dev-reference/compilation.html#logical-combinations).
        const COMBINATION = hs::HS_FLAG_COMBINATION;
        /// Ignore match reporting for this pattern. Used for the sub-patterns in logical combinations.
        const QUIET = hs::HS_FLAG_QUIET;
    }
}

bitflags! {
    /// Flags that allow the set of matches produced by a pattern to be constrained at compile time,
    /// rather than relying on the application to process unwanted matches at runtime.
    #[derive(Debug, Default, Copy, Clone, PartialEq, Eq, Hash)]
    pub struct ExtFlags: u64 {
        /// The minimum end offset in the data stream at which this pattern should match successfully.
        const MIN_OFFSET = hs::HS_EXT_FLAG_MIN_OFFSET;
        /// The maximum end offset in the data stream at which this pattern should match successfully.
        const MAX_OFFSET = hs::HS_EXT_FLAG_MAX_OFFSET;
        /// The minimum match length (from start to end) required to successfully match this pattern.
        const MIN_LENGTH = hs::HS_EXT_FLAG_MIN_LENGTH;
        /// Allow patterns to approximately match within this Levenshtein distance.
        const LEVENSHTEIN_DISTANCE = hs::HS_EXT_FLAG_EDIT_DISTANCE;
        /// Allow patterns to approximately match within this Hamming distance.
        const HAMMING_DISTANCE = hs::HS_EXT_FLAG_HAMMING_DISTANCE;
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
/// The type of edit distance
pub enum EditDistance {
    /// The [Levenshtein distance](https://en.wikipedia.org/wiki/Levenshtein_distance), which allows
    /// deletion, insertion, and substitution
    Levenshtein(u32),
    /// The [Hamming distance](https://en.wikipedia.org/wiki/Hamming_distance), which allows substitution
    Hamming(u32),
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash)]
pub struct Extensions {
    /// The minimum end offset in the data stream at which this pattern should match successfully.
    pub min_offset: Option<u64>,
    /// The maximum end offset in the data stream at which this pattern should match successfully.
    pub max_offset: Option<u64>,
    /// The minimum match length (from start to end) required to successfully match this pattern.
    pub min_length: Option<u64>,
    /// Allow patterns to approximately match within this [edit distance](https://en.wikipedia.org/wiki/Edit_distance).
    pub edit_distance: Option<EditDistance>,
}

impl Extensions {
    pub fn to_ffi(&self) -> hs::hs_expr_ext {
        let mut ext_ffi = hs::hs_expr_ext {
            flags: 0,
            min_offset: 0,
            max_offset: 0,
            min_length: 0,
            edit_distance: 0,
            hamming_distance: 0,
        };

        if let Some(min_offset) = self.min_offset {
            ext_ffi.flags |= ExtFlags::MIN_OFFSET.bits();
            ext_ffi.min_offset = min_offset;
        }
        if let Some(max_offset) = self.max_offset {
            ext_ffi.flags |= ExtFlags::MAX_OFFSET.bits();
            ext_ffi.max_offset = max_offset;
        }
        if let Some(min_length) = self.min_length {
            ext_ffi.flags |= ExtFlags::MIN_LENGTH.bits();
            ext_ffi.min_length = min_length;
        }
        if let Some(edit_distance) = self.edit_distance {
            match edit_distance {
                EditDistance::Levenshtein(distance) => {
                    ext_ffi.flags |= ExtFlags::LEVENSHTEIN_DISTANCE.bits();
                    ext_ffi.edit_distance = distance;
                }
                EditDistance::Hamming(distance) => {
                    ext_ffi.flags |= ExtFlags::HAMMING_DISTANCE.bits();
                    ext_ffi.hamming_distance = distance;
                }
            }
        }

        ext_ffi
    }

    fn from_ffi(expr_ext: hs::hs_expr_ext) -> Self {
        let flags = ExtFlags::from_bits(expr_ext.flags)
            .expect("hs_expr_ext should only have valid flag bits");
        let min_offset = flags
            .contains(ExtFlags::MIN_OFFSET)
            .then_some(expr_ext.min_offset);
        let max_offset = flags
            .contains(ExtFlags::MAX_OFFSET)
            .then_some(expr_ext.max_offset);
        let min_length = flags
            .contains(ExtFlags::MIN_LENGTH)
            .then_some(expr_ext.min_length);

        // We assume that Hyperscan will properly maintain the invariant that only one edit distance bit will be set
        let edit_distance = {
            if flags.contains(ExtFlags::LEVENSHTEIN_DISTANCE) {
                Some(EditDistance::Levenshtein(expr_ext.edit_distance))
            } else if flags.contains(ExtFlags::HAMMING_DISTANCE) {
                Some(EditDistance::Hamming(expr_ext.edit_distance))
            } else {
                None
            }
        };

        Self {
            min_offset,
            max_offset,
            min_length,
            edit_distance,
        }
    }

    /// Creates an Extensions value with all values set to None.
    pub fn empty() -> Self {
        Self::default()
    }
}

impl From<Extensions> for hs::hs_expr_ext {
    fn from(value: Extensions) -> Self {
        value.to_ffi()
    }
}

impl From<hs::hs_expr_ext> for Extensions {
    fn from(value: hs::hs_expr_ext) -> Self {
        Self::from_ffi(value)
    }
}

fn get_expr_info(
    expression: std::ffi::CString,
    flags: ffi::c_uint,
    extensions: hs::hs_expr_ext,
) -> Result<hs::hs_expr_info, Error> {
    let mut hs_expr_info: *mut hs::hs_expr_info_t = std::ptr::null_mut();
    let mut hs_compile_err: *mut hs::hs_compile_error_t = std::ptr::null_mut();

    let hs_error = unsafe {
        hs::hs_expression_ext_info(
            expression.as_ptr(),
            flags,
            &extensions,
            &mut hs_expr_info,
            &mut hs_compile_err,
        )
    };
    check_ffi_result(hs_error, HsCompileError::from_ptr(hs_compile_err))?;

    // Safety: if Hyperscan didn't return an error, it must have initialized `hs_expr_info`
    Ok(unsafe { *hs_expr_info })
}

/// When a [`Pattern`] can produce matches at end of data (EOD)
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum EodMatchBehavior {
    /// Will never produce a match at EOD
    Never,
    /// Can sometimes produce a match at EOD
    Sometimes,
    /// Will only produce a match at EOD
    Only,
}

/// Metadata about the internals of how Hyperscan will treat a [`Pattern`]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct PatternInfo {
    /// The minimum length in bytes of a match for the pattern.
    ///
    /// Note: in some cases when using advanced features to suppress matches (such as extended parameters
    /// or the [`SINGLE_MATCH`](Flags::SINGLE_MATCH) flag) this may represent a conservative lower bound
    /// for the true minimum length of a match.
    pub min_width: u32,
    /// The maximum length in bytes of a match for the pattern. If the pattern has an unbounded maximum length,
    /// this will be set to the maximum value of an unsigned int [`u32::MAX`].
    ///
    /// Note: in some cases when using advanced features to suppress matches (such as extended parameters
    /// or the [`SINGLE_MATCH`](Flags::SINGLE_MATCH) flag) this may represent a conservative lower bound
    /// for the true maximum length of a match.
    pub max_width: u32,
    /// Whether the pattern can produce matches that are not returned in order, such as those produced by assertions
    pub unordered_matches: bool,
    /// How the pattern behaves at EOD
    pub eod_behavior: EodMatchBehavior,
}

impl PatternInfo {
    fn from_ffi(expr_info: hs::hs_expr_info) -> Self {
        let unordered_matches = expr_info.unordered_matches != 0;
        let matches_at_eod = expr_info.matches_at_eod != 0;
        let matches_only_at_eod = expr_info.matches_only_at_eod != 0;
        let eod_behavior = match (matches_at_eod, matches_only_at_eod) {
            (false, _) => EodMatchBehavior::Never,
            (true, false) => EodMatchBehavior::Sometimes,
            (true, true) => EodMatchBehavior::Only,
        };
        Self {
            min_width: expr_info.min_width,
            max_width: expr_info.max_width,
            unordered_matches,
            eod_behavior,
        }
    }
}

#[derive(Debug)]
pub struct PatternBuilder {
    expression: String,
    flags: Option<Flags>,
    extensions: Option<Extensions>,
    id: Option<u32>,
}
impl PatternBuilder {
    /// Returns a new builder
    pub fn new(expression: impl Into<String>) -> Self {
        Self {
            expression: expression.into(),
            flags: None,
            extensions: None,
            id: None,
        }
    }

    /// Sets the [`Flags`] of this Pattern
    pub fn flags(mut self, flags: Flags) -> Self {
        self.flags = Some(flags);
        self
    }

    /// Sets the [`Extensions`] of this Pattern
    pub fn extensions(mut self, extensions: Extensions) -> Self {
        self.extensions = Some(extensions);
        self
    }

    /// Sets the id of this Pattern
    pub fn id(mut self, id: u32) -> Self {
        self.id = Some(id);
        self
    }

    /// Validates the Pattern via Hyperscan and returns it if valid.
    pub fn try_build(self) -> Result<Pattern, Error> {
        Pattern::try_new(self.expression, self.flags, self.extensions, self.id)
    }

    /// Validates the Pattern via Hyperscan, returning it if valid.
    ///
    /// # Panics
    /// This panics if Hyperscan rejects the pattern as invalid.
    #[cfg(test)]
    pub fn build(self) -> Pattern {
        self.try_build().expect("should be a valid Pattern")
    }
}

/// An abstraction over Hyperscan's compilation unit:
/// * expression ([`ffi::CString`])
/// * flags (`HS_FLAG_*`, e.g. [`hs::HS_FLAG_DOTALL`])
/// * extensions ([`hs::hs_expr_info_t`])
///
/// This has been pre-validated by Hyperscan, and short of passing in flags for a different CPU architecture,
/// compilation of this pattern into a database should never fail.
///
// NOTE: This is not intended to be an ergonomic struct for casual construction of Patterns.
// Abstractions should be built over it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Pattern {
    expression: String,
    flags: Flags,
    extensions: Extensions,
    id: u32,
    info: PatternInfo,
}

impl Pattern {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(expression: impl Into<String>) -> PatternBuilder {
        PatternBuilder::new(expression)
    }

    pub(crate) fn try_new(
        expression: impl Into<String>,
        flags: Option<Flags>,
        extensions: Option<Extensions>,
        id: Option<u32>,
    ) -> Result<Self, Error> {
        let expression = expression.into();
        let c_string = expression.try_to_cstring()?;
        let flags = flags.unwrap_or(Flags::empty());
        let extensions = extensions.unwrap_or(Extensions::empty());
        let expr_info = get_expr_info(c_string, flags.bits(), extensions.to_ffi())?;
        let pattern_info = PatternInfo::from_ffi(expr_info);
        Ok(Self {
            expression,
            flags,
            extensions,
            // If a null id is passed in, Hyperscan will default it to 0
            id: id.unwrap_or(0),
            info: pattern_info,
        })
    }

    /// The raw regex pattern, without `/`, and without flags. For example, `"abcdef"`, not `"/abcdef/i"`.
    /// This is guaranteed to be a valid [`std::ffi::CString`]
    pub fn expression(&self) -> &str {
        self.expression.as_str()
    }

    pub fn flags(&self) -> Flags {
        self.flags
    }

    pub fn extensions(&self) -> Extensions {
        self.extensions
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn info(&self) -> PatternInfo {
        self.info
    }

    /// Allocates and returns a CString representation of the Pattern's `expression`. This is guaranteed
    /// not to fail because of an invariant enforced upon struct initialization.
    pub fn to_c_string(&self) -> std::ffi::CString {
        self.expression
            .try_to_cstring()
            .expect("should not have been able to construct Pattern with invalid CString")
    }
}
