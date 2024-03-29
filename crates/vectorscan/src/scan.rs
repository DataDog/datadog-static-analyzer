// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::database::BlockDatabase;
use crate::error::{check_ffi_result, Error};
use crate::runtime::{ErrorCode, Scratch};
use core::ffi;
use std::hash::Hash;
use std::ops::{ControlFlow, Range};
use vectorscan_sys::hs;

/// The pattern id that Hyperscan sends to a [`hs::hs_scan`] callback when it finds a match.
#[derive(Debug, Default, Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct PatternId(pub u32);

impl From<u32> for PatternId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<PatternId> for u32 {
    fn from(value: PatternId) -> Self {
        value.0
    }
}

/// A match result, and the pattern id that triggered it.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, Hash)]
pub struct HsMatch {
    id: PatternId,
    // NOTE: We currently split out start_idx and end_idx because we want `Copy`, but `std::ops::Range` is not.
    // (See [RFC #3500](https://github.com/rust-lang/rfcs/pull/3550) for potential 2024 Edition "fix" for this)
    start_idx: usize,
    end_idx: usize,
}

impl HsMatch {
    pub fn new(id: u32, start_idx: usize, end_idx: usize) -> Self {
        Self {
            id: PatternId(id),
            start_idx,
            end_idx,
        }
    }
    pub fn pattern_id(&self) -> PatternId {
        self.id
    }
    pub fn start(&self) -> usize {
        self.start_idx
    }
    pub fn end(&self) -> usize {
        self.end_idx
    }
    pub fn as_range(&self) -> Range<usize> {
        self.start_idx..self.end_idx
    }
}

/// The status of a successfully completed Hyperscan scan
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ScanStatus {
    /// The buffer was completely read, there may or may not have been a match,
    /// and the caller did not request a termination.
    Completed,
    /// There was at least one match, and the caller requested a termination at some point.
    Halted,
}

impl BlockDatabase {
    /// Synchronously scans a slice of bytes, calling the provided callback for every match for
    /// any pattern in the database.
    pub fn scan<T, U>(
        &self,
        scratch: &mut Scratch,
        bytes: T,
        callback: Box<U>,
    ) -> Result<ScanStatus, Error>
    where
        T: AsRef<[u8]>,
        U: FnMut(HsMatch) -> ControlFlow<()>,
    {
        // NOTE: `scratch` is a mutable borrow to prevent the callback from re-calling into the database
        // to initiate another scan, which will lead to an error.
        // See: https://intel.github.io/hyperscan/dev-reference/api_files.html#c.HS_SCRATCH_IN_USE
        let raw_cb = Box::into_raw(callback);

        let hs_error = unsafe {
            hs::hs_scan(
                self.as_ptr(),
                bytes.as_ref().as_ptr() as *const ffi::c_char,
                bytes.as_ref().len() as ffi::c_uint,
                // This field is [unused by Hyperscan](https://intel.github.io/hyperscan/dev-reference/api_files.html#c.hs_scan)
                0 as ffi::c_uint,
                scratch.as_ptr(),
                Some(Self::hs_match_handler::<U>),
                raw_cb as *mut ffi::c_void,
            )
        };
        // Let Box's `drop` free memory.
        // Safety: The Hyperscan library never touches the memory this pointer dereferences to, so this
        // is the complement to the `Box::into_raw` call we made earlier.
        let _ = unsafe { Box::from_raw(raw_cb) };

        let ffi_result = check_ffi_result(hs_error, None);
        match ffi_result {
            Ok(_) => Ok(ScanStatus::Completed),
            Err(Error::Runtime(ErrorCode::SCAN_TERMINATED)) => Ok(ScanStatus::Halted),
            Err(err) => Err(err),
        }
    }

    /// Searches an input for the first occurrence of any pattern in the Database.
    pub fn find<T>(&self, scratch: &mut Scratch, bytes: T) -> Result<Option<HsMatch>, Error>
    where
        T: AsRef<[u8]>,
    {
        let mut found: Option<HsMatch> = None;
        self.scan(
            scratch,
            bytes,
            Box::new(|hs_match| {
                found.replace(hs_match);
                ControlFlow::Break(())
            }),
        )?;
        Ok(found)
    }

    /// Synchronously scans a slice of bytes until completion and returns a Vec of the matches.
    pub fn scan_collect<T>(&self, scratch: &mut Scratch, bytes: T) -> Result<Vec<HsMatch>, Error>
    where
        T: AsRef<[u8]>,
    {
        let mut matches = Vec::<HsMatch>::new();
        self.scan(
            scratch,
            bytes,
            Box::new(|hs_match| {
                matches.push(hs_match);
                ControlFlow::Continue(())
            }),
        )?;
        Ok(matches)
    }

    /// The callback function passed to Hyperscan to handle an event generated by [BlockDatabase::scan]
    extern "C" fn hs_match_handler<T>(
        id: ffi::c_uint,
        from: ffi::c_ulonglong,
        to: ffi::c_ulonglong,
        _flags: ffi::c_uint,
        context: *mut ffi::c_void,
    ) -> ffi::c_int
    where
        T: FnMut(HsMatch) -> ControlFlow<()>,
    {
        // Safety: This is safe because for `hs_scan`, we passed Hyperscan the raw pointer to our boxed closure,
        // and Hyperscan just echoes this pointer back to us without touching it.
        let callback = unsafe { &mut *(context as *mut T) };

        let hs_match = HsMatch::new(id, from as usize, to as usize);

        match callback(hs_match) {
            ControlFlow::Continue(_) => 0,
            ControlFlow::Break(_) => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::compiler::Pattern;
    use crate::database::BlockDatabase;
    use crate::runtime::Scratch;
    use crate::scan::{HsMatch, ScanStatus};
    use std::ops::ControlFlow;

    #[test]
    fn test_scan_control_flow() {
        let haystack = "abc----------abc---------ac----";
        let expr1 = Pattern::new("ab?c").id(1234).build();
        let db = BlockDatabase::try_new([&expr1]).unwrap();
        let mut scratch = Scratch::try_new_for(&db).unwrap();

        let mut results: Vec<HsMatch> = vec![];
        let scan_res = db.scan(
            &mut scratch,
            haystack.as_bytes(),
            Box::new(|hs_match| {
                results.push(hs_match);
                ControlFlow::Continue(())
            }),
        );

        assert!(matches!(scan_res, Ok(ScanStatus::Completed)));
        assert_eq!(
            results,
            Vec::from([
                HsMatch::new(1234, 0, 3),
                HsMatch::new(1234, 0, 16),
                HsMatch::new(1234, 0, 27),
            ])
        );

        let mut results: Vec<HsMatch> = vec![];
        // Scan again, but this time terminate after the first match
        let scan_res = db.scan(
            &mut scratch,
            haystack.as_bytes(),
            Box::new(|hs_match| {
                results.push(hs_match);
                ControlFlow::Break(())
            }),
        );

        assert!(matches!(scan_res, Ok(ScanStatus::Halted)));
        assert_eq!(results, Vec::from([HsMatch::new(1234, 0, 3)]));
    }

    #[test]
    fn test_find() {
        let pattern = Pattern::new("abc").id(1234).build();
        let db = BlockDatabase::try_new([&pattern]).unwrap();
        let mut scratch = Scratch::try_new_for(&db).unwrap();

        let find_result = db.find(&mut scratch, "---abc---abc").unwrap();
        assert_eq!(find_result, Some(HsMatch::new(1234, 0, 6)));

        let find_result = db.find(&mut scratch, "------------").unwrap();
        assert_eq!(find_result, None);
    }

    #[test]
    fn test_scan_collect() {
        let haystack = "abc-----abc--abc-------abc";
        let pattern = Pattern::new("abc").id(1234).build();
        let db = BlockDatabase::try_new([&pattern]).unwrap();
        let mut scratch = Scratch::try_new_for(&db).unwrap();

        let mut matches_cb: Vec<HsMatch> = vec![];
        let scan_res = db.scan(
            &mut scratch,
            haystack.as_bytes(),
            Box::new(|hs_match| {
                matches_cb.push(hs_match);
                ControlFlow::Continue(())
            }),
        );
        assert!(matches!(scan_res, Ok(ScanStatus::Completed)));
        assert_eq!(matches_cb.len(), 4);

        let matches_scan_collect = db.scan_collect(&mut scratch, haystack.as_bytes()).unwrap();
        assert_eq!(matches_cb, matches_scan_collect);
    }

    #[test]
    fn test_multi_pattern_scan() {
        let haystack = "---abc---ac----ab-----bc----cba-";
        let expr1 = Pattern::new("ab?c").id(1).build();
        let expr2 = Pattern::new("a?b").id(2).build();
        let db = BlockDatabase::try_new([&expr1, &expr2]).unwrap();
        let mut scratch = Scratch::try_new_for(&db).unwrap();

        let matches = db.scan_collect(&mut scratch, haystack.as_bytes()).unwrap();
        assert_eq!(
            matches,
            Vec::from([
                HsMatch::new(2, 0, 5),
                HsMatch::new(1, 0, 6),
                HsMatch::new(1, 0, 11),
                HsMatch::new(2, 0, 17),
                HsMatch::new(2, 0, 23),
                HsMatch::new(2, 0, 30),
            ])
        )
    }

    /// Ensures that the database doesn't enforce uniqueness of [`PatternId`]
    #[test]
    fn test_colliding_ids() {
        let haystack = "AAAA---ZZZ----AAA";
        let expr1 = Pattern::new("AAA").id(1).build();
        let expr2 = Pattern::new("ZZZ").id(1).build();
        let db = BlockDatabase::try_new([&expr1, &expr2]).unwrap();
        let mut scratch = Scratch::try_new_for(&db).unwrap();

        let matches = db.scan_collect(&mut scratch, haystack.as_bytes()).unwrap();
        assert_eq!(
            matches,
            Vec::from([
                HsMatch::new(1, 0, 3),
                HsMatch::new(1, 0, 4),
                HsMatch::new(1, 0, 10),
                HsMatch::new(1, 0, 17),
            ])
        )
    }
}
