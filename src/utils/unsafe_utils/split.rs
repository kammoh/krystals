use core::slice::*;

/// copy of unstable core::slice::iter::ArrayChunks
#[cfg(not(any(has_array_chunks, feature = "array_chunks")))]
#[must_use]
pub struct ArrayChunks<'a, T: 'a, const N: usize> {
    iter: Iter<'a, [T; N]>,
    rem: &'a [T],
}

/// copy of unstable core::slice::iter::ArrayChunksMut
#[cfg(not(any(has_array_chunks, feature = "array_chunks")))]
#[must_use]
pub struct ArrayChunksMut<'a, T: 'a, const N: usize> {
    iter: IterMut<'a, [T; N]>,
    rem: &'a mut [T],
}

#[cfg(any(has_array_chunks, feature = "array_chunks"))]
use core::slice::ArrayChunks;

#[cfg(any(has_array_chunks, feature = "array_chunks"))]
use core::slice::ArrayChunksMut;

/// alternative version of ArrayChunks
#[must_use]
pub struct ArrayChunksAlt<'a, T: 'a, const N: usize>(&'a [T]);

#[cfg(not(any(has_array_chunks, feature = "array_chunks")))]
impl<'a, T, const N: usize> ArrayChunks<'a, T, N> {
    /// based on unstable core::slice::array_chunks_mut and `as_chunks_mut`
    #[inline]
    pub(super) fn new(slice: &'a [T]) -> Self {
        assert_ne!(N, 0);

        let len = slice.len();
        let num_chunks = len / N;
        let (multiple_of_n, rem) = slice.split_at(num_chunks * N);

        // SAFETY: We already panicked for zero, and ensured by construction
        // that the length of the subslice is a multiple of N.
        // SAFETY: We cast a slice of `num_chunks * N` elements into
        // a slice of `num_chunks` many `N` elements chunks.
        #[allow(unsafe_code)]
        let array_slice: &'a [[T; N]] =
            unsafe { from_raw_parts(multiple_of_n.as_ptr() as _, num_chunks) };

        debug_assert_eq!(array_slice.len(), num_chunks);
        debug_assert_eq!(num_chunks * N + rem.len(), len);

        Self {
            iter: array_slice.iter(),
            rem,
        }
    }

    /// Returns the remainder of the original slice that is not going to be
    /// returned by the iterator. The returned slice has at most `N-1`
    /// elements.
    #[allow(dead_code)]
    #[must_use = "`self` will be dropped if the result is not used"]
    pub fn into_remainder(self) -> &'a [T] {
        self.rem
    }
}

#[cfg(not(any(has_array_chunks, feature = "array_chunks")))]
impl<'a, T, const N: usize> ArrayChunksMut<'a, T, N> {
    /// based on unstable core::slice::array_chunks_mut and `as_chunks_mut`
    #[inline]
    pub(super) fn new(slice: &'a mut [T]) -> Self {
        assert_ne!(N, 0);

        let len = slice.len();
        let num_chunks = len / N;
        let (multiple_of_n, rem) = slice.split_at_mut(num_chunks * N);

        // SAFETY: We already panicked for zero, and ensured by construction
        // that the length of the subslice is a multiple of N.
        // SAFETY: We cast a slice of `num_chunks * N` elements into
        // a slice of `num_chunks` many `N` elements chunks.
        #[allow(unsafe_code)]
        let array_slice: &mut [[T; N]] =
            unsafe { from_raw_parts_mut(multiple_of_n.as_mut_ptr() as _, num_chunks) };

        debug_assert_eq!(array_slice.len(), num_chunks);
        debug_assert_eq!(num_chunks * N + rem.len(), len);

        Self {
            iter: array_slice.iter_mut(),
            rem,
        }
    }

    /// Returns the remainder of the original slice that is not going to be
    /// returned by the iterator. The returned slice has at most `N-1`
    /// elements.
    #[allow(dead_code)]
    #[must_use = "`self` will be dropped if the result is not used"]
    pub fn into_remainder(self) -> &'a mut [T] {
        self.rem
    }
}

#[must_use]
pub struct FullArrayChunks<'a, T: 'a, const N: usize>(Option<&'a [T]>);

#[must_use]
pub struct PaddedArrayChunks<'a, const N: usize, const PAD_BYTE: u8>(Option<&'a [u8]>);

pub(crate) trait Splitter<'a, T> {
    fn try_split_array_ref<const N: usize>(&self) -> (Option<&[T; N]>, &[T]);
    fn try_split_array_mut<const N: usize>(&mut self) -> (Option<&mut [T; N]>, &mut [T]);

    fn into_array_chunks_iter<const N: usize>(&self) -> ArrayChunks<'_, T, N>;
    fn into_array_chunks_mut<const N: usize>(&mut self) -> ArrayChunksMut<'_, T, N>;
}
pub(crate) trait ArraySplitter<T> {
    fn dissect_ref<const N1: usize, const N2: usize>(&self) -> (&[T; N1], &[T; N2]);
}
pub(crate) trait ArraySplitterMut<T> {
    fn dissect_mut<const N1: usize, const N2: usize>(&mut self) -> (&mut [T; N1], &mut [T; N2]);
}

impl<T: Sized, const N: usize> ArraySplitter<T> for [T; N] {
    fn dissect_ref<const N1: usize, const N2: usize>(&self) -> (&[T; N1], &[T; N2]) {
        assert_eq!(N1 + N2, N);
        let (left, right) = self.split_at(N1);
        #[allow(unsafe_code)]
        // SAFETY: 'left' points to [T; N1] as it's [T] of length N1 (checked by split_at)
        //         'right' points to [T; N2] as it's [T] of length (N - N1) = N2 (above assert would paniced otherwise)
        unsafe {
            (
                &*(left.as_ptr() as *const [T; N1]),
                &*(right.as_ptr() as *const [T; N2]),
            )
        }
    }
}
impl<T: Sized, const N: usize> ArraySplitterMut<T> for [T; N] {
    fn dissect_mut<const N1: usize, const N2: usize>(&mut self) -> (&mut [T; N1], &mut [T; N2]) {
        assert_eq!(N1 + N2, N);
        let (left, right) = self.split_at_mut(N1);
        #[allow(unsafe_code)]
        // SAFETY: 'left' points to [T; N1] as it's [T] of length N1 (checked by split_at)
        //         'right' points to [T; N2] as it's [T] of length (N - N1) = N2 (above assert would paniced otherwise)
        unsafe {
            (
                &mut *(left.as_mut_ptr() as *mut [T; N1]),
                &mut *(right.as_mut_ptr() as *mut [T; N2]),
            )
        }
    }
}

impl<T: Sized, const N: usize> ArraySplitter<T> for &[T; N] {
    fn dissect_ref<const N1: usize, const N2: usize>(&self) -> (&[T; N1], &[T; N2]) {
        (*self).dissect_ref()
    }
}

impl<T: Sized, const N: usize> ArraySplitterMut<T> for &mut [T; N] {
    fn dissect_mut<const N1: usize, const N2: usize>(&mut self) -> (&mut [T; N1], &mut [T; N2]) {
        (*self).dissect_mut()
    }
}

pub(crate) trait BytesSplitter<'a> {
    fn into_padded_array_chunks<const N: usize, const PAD_BYTE: u8>(
        &'a self,
    ) -> PaddedArrayChunks<'a, N, PAD_BYTE>;
}

impl BytesSplitter<'_> for [u8] {
    #[inline]
    fn into_padded_array_chunks<const N: usize, const PAD_BYTE: u8>(
        &self,
    ) -> PaddedArrayChunks<'_, N, PAD_BYTE> {
        PaddedArrayChunks(Some(self))
    }
}

impl<'a, T: 'a> Splitter<'a, T> for [T] {
    // based on `core::slice::split_array_ref` (ATM `unstable` with feature `split_array`).
    // this version avoids extra length check and returns an `Option<&[T; N]>` for the head slice, if enough elements are available
    // otherwise, it returns `None`
    // Safety requirements: none
    #[inline(always)]
    #[must_use]
    fn try_split_array_ref<const N: usize>(&self) -> (Option<&[T; N]>, &[T]) {
        #![allow(unsafe_code)]
        if self.len() < N {
            (None, self)
        } else {
            // SAFETY: self.len() >= N, therefore `[ptr; N]` and `[N; len]` are inside `self`, which
            // fulfills the requirements of `get_unchecked` (using `from_raw_parts_mut`).
            let (a, rest) = unsafe { (self.get_unchecked(..N), self.get_unchecked(N..)) };
            // SAFETY: a points to [T; N]? Yes it's [T] of length N (checked by split_at)
            unsafe { (Some(&*(a.as_ptr() as *const [T; N])), rest) }
        }
    }

    // mutable version of `try_split_array_ref`
    #[inline]
    #[must_use]
    fn try_split_array_mut<const N: usize>(&mut self) -> (Option<&mut [T; N]>, &mut [T]) {
        #![allow(unsafe_code)]
        let len = self.len();
        let ptr = self.as_mut_ptr();
        if len < N {
            (None, self)
        } else {
            // SAFETY: self.len() >= N, therefore `[self; N]` and `[N; len]` are:
            // 1) non-overlapping, so returning mutable references is fine.
            // 2) inside `self` which fulfills the requirements of both `from_raw_parts_mut`
            let (a, rest) = unsafe {
                (
                    from_raw_parts_mut(ptr, N),
                    from_raw_parts_mut(ptr.add(N), len - N),
                )
            };
            // SAFETY: a points to [T; N]? Yes it's [T] of length N (checked by split_at_mut)
            unsafe { (Some(&mut *(a.as_mut_ptr() as *mut [T; N])), rest) }
        }
    }

    #[inline]
    #[must_use]
    fn into_array_chunks_iter<const N: usize>(&self) -> ArrayChunks<'_, T, N> {
        ArrayChunks::new(self)
    }

    #[inline]
    #[must_use]
    fn into_array_chunks_mut<const N: usize>(&mut self) -> ArrayChunksMut<'_, T, N> {
        ArrayChunksMut::new(self)
    }
}

impl<'a, T: 'a, const N: usize> Iterator for ArrayChunksAlt<'a, T, N> {
    type Item = &'a [T; N];

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        let (head, rest) = self.0.try_split_array_ref::<N>();
        self.0 = rest;
        head
    }
}

#[cfg(not(any(has_array_chunks, feature = "array_chunks")))]
impl<'a, T: 'a, const N: usize> Iterator for ArrayChunks<'a, T, N> {
    type Item = &'a [T; N];

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }

    #[inline]
    fn count(self) -> usize {
        self.iter.count()
    }

    #[inline]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.iter.nth(n)
    }

    #[inline]
    fn last(self) -> Option<Self::Item> {
        self.iter.last()
    }
}

#[cfg(not(any(has_array_chunks, feature = "array_chunks")))]
impl<'a, T: 'a, const N: usize> Iterator for ArrayChunksMut<'a, T, N> {
    type Item = &'a mut [T; N];

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }

    #[inline]
    fn count(self) -> usize {
        self.iter.count()
    }

    #[inline]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.iter.nth(n)
    }

    #[inline]
    fn last(self) -> Option<Self::Item> {
        self.iter.last()
    }
}

impl<'a, const N: usize> Iterator for FullArrayChunks<'a, u8, N> {
    type Item = [u8; N];

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(ref mut inner) = self.0 {
            Some(if let (Some(head), tail) = inner.try_split_array_ref() {
                *inner = tail;
                *head
            } else {
                let mut buffer = [0u8; N];
                buffer[0..inner.len()].copy_from_slice(inner);
                self.0 = None;
                buffer
            })
        } else {
            None
        }
    }
}

impl<'a, const N: usize, const PAD_BYTE: u8> Iterator for PaddedArrayChunks<'a, N, PAD_BYTE> {
    type Item = [u8; N];

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(ref mut cursor) = self.0 {
            Some(if let (Some(head), tail) = cursor.try_split_array_ref() {
                *cursor = tail;
                *head
            } else {
                let len = cursor.len();
                // Safety: len <= N - 1, as `try_split_array_ref` has returned `None`
                let mut buffer = [0u8; N];
                buffer[0..len].copy_from_slice(cursor);
                if PAD_BYTE != 0 {
                    buffer[len] = PAD_BYTE;
                }
                self.0 = None;
                buffer
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std; // needed by miri
    use std::vec;

    use super::*;

    #[test]
    fn test_try_split_array_ref() {
        let v = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
        let (a, b) = v.try_split_array_ref::<4>();
        assert_eq!(a.expect("`a` should not be None!"), &[1, 2, 3, 4]);
        assert_eq!(b, &[5, 6, 7, 8, 9, 10, 11, 12, 13]);
        let (a, b) = b.try_split_array_ref::<4>();
        assert_eq!(a.expect("`a` should not be None!"), &[5, 6, 7, 8]);
        assert_eq!(b, &[9, 10, 11, 12, 13]);
        let (a, b) = b.try_split_array_ref::<3>();
        assert_eq!(a.expect("`a` should not be None!"), &[9, 10, 11]);
        assert_eq!(b, &[12, 13]);

        // not enough elements, should return None
        let v = vec![1, 2, 3];
        let (a, b) = v.try_split_array_ref::<4>();
        assert!(a.is_none());
        assert_eq!(b, &[1, 2, 3]);

        // split size same as slice size
        let v = vec![1, 2, 3];
        let (a, b) = v.try_split_array_ref::<3>();
        assert_eq!(a.unwrap(), &[1, 2, 3]);
        assert!(b.is_empty());

        // empty slice
        let v = [0u8; 0];
        assert!(v.is_empty());
        let (a, b) = v.try_split_array_ref::<4>();
        assert!(a.is_none());
        assert_eq!(b, v);
    }

    #[test]
    fn test_try_split_array_mut() {
        let mut v = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let (a, _b) = v.try_split_array_mut::<4>();
        let head = a.unwrap();

        assert_eq!(head, &[1, 2, 3, 4]);

        head.copy_from_slice(&[15, 16, 17, 18]);

        assert_eq!(v, &[15, 16, 17, 18, 5, 6, 7, 8, 9, 10, 11, 12]);
    }
    #[test]
    fn test_split_fail() {}

    #[test]
    fn array_chunks_exact() {
        let v = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let mut chunks = v.into_array_chunks_iter::<4>();
        assert_eq!(chunks.next().unwrap(), &[1, 2, 3, 4]);
        assert_eq!(chunks.next().unwrap(), &[5, 6, 7, 8]);
        assert_eq!(chunks.next().unwrap(), &[9, 10, 11, 12]);
        assert!(chunks.next().is_none());
        assert!(chunks.into_remainder().is_empty());
    }

    #[test]
    fn array_chunks_with_remainder() {
        let v = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        let mut chunks = v.into_array_chunks_iter::<4>();
        assert_eq!(chunks.next().unwrap(), &[1, 2, 3, 4]);
        assert_eq!(chunks.next().unwrap(), &[5, 6, 7, 8]);
        assert_eq!(chunks.next().unwrap(), &[9, 10, 11, 12]);
        assert!(chunks.next().is_none());
        assert_eq!(chunks.into_remainder(), &[13, 14]);
    }

    #[test]
    fn array_chunks_mut() {
        let mut v = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        for chunks in v.into_array_chunks_mut::<4>() {
            for (i, x) in chunks.iter_mut().enumerate() {
                *x *= *x + i;
            }
        }
        assert_eq!(v, vec![1, 6, 15, 28, 25, 42, 63, 88, 9]);
    }
}
