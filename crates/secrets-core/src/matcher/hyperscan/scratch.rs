// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use std::ops::{Index, IndexMut};
use vectorscan::scan::PatternId;
use vectorscan::HsMatch;

/// A scratch buffer for Hyperscan to write [`HsMatch`] structs into.
#[derive(Debug, Clone)]
pub(crate) struct Scratch {
    buffers: Buffers,
    soft_max_len: Option<usize>,
    /// A list of buffers that have spilled over the `target_max_len` and need to be shrunk.
    to_shrink: Vec<PatternId>,
    /// A list of buffers that have been written to and need to be cleared before writing anew.
    to_clear: Vec<PatternId>,
}

impl Scratch {
    /// Creates and appropriately sizes a [`Scratch`] given a PatternSet.
    pub fn new(pattern_count: usize) -> Self {
        let mut buffers = Vec::<Vec<HsMatch>>::with_capacity(pattern_count);
        for _ in 0..pattern_count {
            buffers.push(Vec::new())
        }
        let buffers = Buffers(buffers);
        Self {
            buffers,
            soft_max_len: None,
            to_shrink: Vec::new(),
            to_clear: Vec::new(),
        }
    }

    /// Creates a [`Scratch`] with an initial capacity of 0 and a target max length.
    /// The inner buffer will be shrunk to the target maximum length before a scan.
    ///
    /// NOTE: the buffer can still grow larger than this value during and after a scan.
    pub fn with_target_max_len(pattern_count: usize, target_max_len: usize) -> Self {
        let mut scratch = Self::new(pattern_count);
        scratch.soft_max_len = Some(target_max_len);
        scratch
    }

    /// Acquires a [`ScratchGuard`] that provides methods for mutation of the underlying buffer.
    pub fn get_mut(&mut self) -> ScratchGuard {
        ScratchGuard::new(self)
    }

    pub fn get(&self, pattern_id: PatternId) -> Option<&[HsMatch]> {
        if (pattern_id.0 as usize) < self.buffers.pattern_count() {
            Some(self.buffers[pattern_id].as_slice())
        } else {
            None
        }
    }

    /// Returns a reference to the inner buffer backing this data. This is currently only exposed
    /// to allow the [`MatchCursor`](crate::matcher::hyperscan::MatchCursor) to traverse the innards
    /// without needing complex generic impls.
    pub(crate) fn buffers(&self) -> &Vec<Vec<HsMatch>> {
        &self.buffers.0
    }
}

/// A guard that guarantees to the caller that:
/// * Upon taking this mutable reference, the scratch is empty.
/// * After dropping this mutable reference, the scratch will be sorted.
pub(crate) struct ScratchGuard<'a>(&'a mut Scratch);

impl<'a> ScratchGuard<'a> {
    pub fn new(scratch: &'a mut Scratch) -> Self {
        if let Some(target_max_len) = scratch.soft_max_len {
            for pattern_id in scratch.to_shrink.drain(..) {
                scratch.buffers[pattern_id].shrink_to(target_max_len);
            }
        }
        for pattern_id in scratch.to_clear.drain(..) {
            scratch.buffers[pattern_id].clear();
        }

        Self(scratch)
    }
    /// Appends an [`HsMatch`] to the back of the buffer.
    #[inline]
    pub fn push(&mut self, hs_match: HsMatch) {
        self.0.buffers[hs_match.pattern_id()].push(hs_match);
    }
}

impl Drop for ScratchGuard<'_> {
    fn drop(&mut self) {
        // For efficient post-processing, `Scratch` requires that the buffer is sorted by
        // end byte ascending.
        // NOTE: the `HsMatch` "start" byte is not used, as due to Hyperscan semantics, it'll always be zero.
        for (pattern_id, buffer) in self.0.buffers.iter_mut() {
            // Buffers are stored in ascending pattern id, with no gaps.
            if !buffer.is_empty() {
                buffer.sort_unstable_by_key(|hs_match| hs_match.end());
                self.0.to_clear.push(pattern_id);
                if self
                    .0
                    .soft_max_len
                    .is_some_and(|max_len| buffer.capacity() > max_len)
                {
                    self.0.to_shrink.push(pattern_id);
                }
            }
        }
    }
}

/// The internal data structure behind [`Scratch`] is a jagged array with sorted member arrays.
///
/// Each [`PatternId`] has its own vector that lives for the lifetime of Scratch. The memory
/// usage of each [`PatternId`] is determined by how many [`HsMatch`] structs are stored before
/// the scratch is cleared.
///
/// Initially, each pattern starts with an empty, zero-capacity vector.
#[derive(Debug, Clone)]
#[repr(transparent)]
struct Buffers(Vec<Vec<HsMatch>>);

impl Buffers {
    /// Returns an iterator that yields a reference to each Pattern's buffer
    pub fn iter(&self) -> impl Iterator<Item = (PatternId, &Vec<HsMatch>)> {
        self.0
            .iter()
            .enumerate()
            .map(|(idx, buffer)| (PatternId(idx as u32), buffer))
    }

    /// Returns an iterator that yields a mutable reference to each Pattern's buffer
    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = (PatternId, &mut Vec<HsMatch>)> {
        self.0
            .iter_mut()
            .enumerate()
            .map(|(idx, buffer)| (PatternId(idx as u32), buffer))
    }

    /// The number of Patterns the scratch supports.
    pub fn pattern_count(&self) -> usize {
        self.0.len()
    }
}

impl Index<PatternId> for Buffers {
    type Output = Vec<HsMatch>;

    fn index(&self, index: PatternId) -> &Self::Output {
        self.0
            .get(index.0 as usize)
            .expect("PatternId should not be out of bounds")
    }
}

impl IndexMut<PatternId> for Buffers {
    fn index_mut(&mut self, index: PatternId) -> &mut Self::Output {
        self.0
            .get_mut(index.0 as usize)
            .expect("PatternId should not be out of bounds")
    }
}

#[cfg(test)]
mod tests {
    use super::Scratch;
    use vectorscan::scan::PatternId;
    use vectorscan::HsMatch;

    fn hs_match(id: u32, end_idx: usize) -> HsMatch {
        HsMatch::new(id, 0, end_idx)
    }

    fn scratch_from(hs_matches: &[HsMatch]) -> Scratch {
        let max_id = hs_matches.iter().map(|hsm| hsm.pattern_id()).max().unwrap();
        // (PatternId is zero-based)
        let len = 1 + max_id.0 as usize;
        let mut scratch = Scratch::new(len);
        let mut guard = scratch.get_mut();

        for hs_match in hs_matches.iter().copied() {
            guard.push(hs_match);
        }
        drop(guard);
        scratch
    }

    /// [`HsMatch`] slice should be sorted by end index ascending.
    #[rustfmt::skip]
    #[test]
    fn sorted_hs_matches() {
        let scratch = scratch_from(&[hs_match(3, 10), hs_match(3, 4), hs_match(3, 8)]);
        let iter = scratch.buffers[PatternId(3)].iter().copied();
        let hs_matches = iter.collect::<Vec<_>>();
        assert_eq!(hs_matches, vec![hs_match(3, 4), hs_match(3, 8), hs_match(3, 10)]);
    }

    /// Scratch memory can be reclaimed if it temporarily goes over a soft limit.
    #[test]
    fn truncate_buffers() {
        let mut scratch = scratch_from(&[hs_match(2, 4)]);
        let target_max = 2;
        scratch.soft_max_len = Some(target_max);
        assert_eq!(scratch.buffers[PatternId(1)].capacity(), 0);

        let id = PatternId(1);
        assert!(!scratch.to_clear.contains(&id));
        let mut guard = scratch.get_mut();
        let count = 20;
        for i in 0..count {
            guard.push(hs_match(id.0, i * 2))
        }
        assert!(guard.0.buffers[id].capacity() >= count);
        drop(guard);

        // The `to_clear` Vec should be populated now, but the capacity should still be `target_max`
        assert_eq!(scratch.to_clear, vec![id]);
        assert!(scratch.buffers[id].capacity() > count);

        // The capacity should be truncated after the next acquisition of the guard.
        let guard = scratch.get_mut();
        drop(guard);
        assert!(scratch.buffers[id].capacity() <= count);
    }

    /// Scratch is cleared when the Guard is acquired.
    #[rustfmt::skip]
    #[test]
    fn scratch_is_cleared() {
        let id = PatternId(0);
        let mut scratch = scratch_from(&[hs_match(id.0, 1)]);
        let hs_matches = scratch.buffers[id].as_slice();
        assert_eq!(hs_matches, vec![hs_match(id.0, 1)]);

        let mut guard = scratch.get_mut();
        assert!(!guard.0.to_clear.contains(&id));
        assert_eq!(guard.0.buffers[id].len(), 0);

        guard.push(hs_match(id.0, 20));
        guard.push(hs_match(id.0, 30));
        drop(guard);

        let hs_matches = scratch.buffers[id].as_slice();
        assert_eq!(hs_matches, vec![hs_match(id.0, 20), hs_match(id.0, 30)]);
    }
}
