use core::slice::*;

#[must_use]
pub struct ArrayChunks<'a, T: 'a, const N: usize>(&'a [T]);

#[must_use]
pub struct ArrayChunksMut<'a, T: 'a, const N: usize> {
    iter: IterMut<'a, [T; N]>,
}

#[must_use]
#[inline(always)]
fn transmute_to_chunks_mut<T, const N: usize>(slice: &mut [T]) -> &mut [[T; N]] {
    #![allow(unsafe_code)]
    let len = slice.len();
    assert!(N != 0 && len % N == 0);

    // SAFETY: We cast a slice of `new_len * N` elements into
    // a slice of `new_len` many `N` elements chunks.
    unsafe { from_raw_parts_mut(slice.as_mut_ptr() as _, len / N) }
}

impl<'a, T, const N: usize> ArrayChunksMut<'a, T, N> {
    #[inline]
    pub(super) fn new(slice: &'a mut [T]) -> Self {
        Self {
            iter: transmute_to_chunks_mut(slice).iter_mut(),
        }
    }
}

#[must_use]
pub struct FullArrayChunks<'a, T: 'a, const N: usize>(Option<&'a [T]>);

#[must_use]
pub struct PadExtraArrayChunks<'a, const N: usize, const PAD_BYTE: u8>(Option<&'a [u8]>);

pub(crate) trait Splitter<'a, T> {
    fn try_split_array_ref<const N: usize>(&self) -> (Option<&[T; N]>, &[T]);
    fn try_split_array_mut<const N: usize>(&mut self) -> (Option<&mut [T; N]>, &mut [T]);

    fn into_array_ref_iter<const N: usize>(&self) -> ArrayChunks<'_, T, N>;
    fn into_array_mut_iter<const N: usize>(&mut self) -> ArrayChunksMut<'_, T, N>;
}

pub(crate) trait BytesSplitter<'a> {
    fn array_chunks_with_padding<const N: usize, const PAD_BYTE: u8>(
        &'a self,
    ) -> PadExtraArrayChunks<'a, N, PAD_BYTE>;
}

impl BytesSplitter<'_> for [u8] {
    fn array_chunks_with_padding<const N: usize, const PAD_BYTE: u8>(
        &self,
    ) -> PadExtraArrayChunks<'_, N, PAD_BYTE> {
        PadExtraArrayChunks(Some(self))
    }
}

impl<'a, T: 'a> Splitter<'a, T> for [T] {
    // based on `core::slice::split_array_ref` (ATM requires `unstable` with feature `split_array`).
    // this version avoids extra length check and returns an `Option<&[T; N]>` for the head slice, if enough elements are available
    // otherwise, it returns `None`
    // Safety requirements: none
    #[inline]
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
            // SAFETY: self.len() >= N, therefore `[self; N]` and `[N; len]` are inside `self`,  `get_unchecked_mut`.
            //
            // SAFETY: self.len() >= N, therefore `[self; N]` and `[N; len]`
            // 1) are not overlapping, so returning a mutable reference is fine.
            // 2) are inside `self` which fulfills the requirements of both `from_raw_parts_mut`
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
    fn into_array_ref_iter<const N: usize>(&self) -> ArrayChunks<'_, T, N> {
        ArrayChunks(self)
    }

    #[inline]
    #[must_use]
    fn into_array_mut_iter<const N: usize>(&mut self) -> ArrayChunksMut<'_, T, N> {
        ArrayChunksMut::new(self)
    }
}

impl<'a, T: 'a, const N: usize> Iterator for ArrayChunks<'a, T, N> {
    type Item = &'a [T; N];

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let (head, rest) = self.0.try_split_array_ref::<N>();
        self.0 = rest;
        head
    }
}

impl<'a, T: 'a, const N: usize> Iterator for ArrayChunksMut<'a, T, N> {
    type Item = &'a mut [T; N];

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
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

impl<'a, const N: usize, const PAD_BYTE: u8> Iterator for PadExtraArrayChunks<'a, N, PAD_BYTE> {
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
}
