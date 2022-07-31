pub trait FlattenArray<T, const L: usize, const M: usize, const N: usize> {
    fn flatten_array(&self) -> &[T; N];
}
pub trait FlattenArrayMut<T, const L: usize, const M: usize, const N: usize> {
    fn flatten_array_mut(&mut self) -> &mut [T; N];
}

pub(crate) trait FlattenArrayCheck<const L: usize, const M: usize, const N: usize> {
    const REQUIREMENT: bool = L * M == N;
    const __ASSERT: &'static str =
        ["FlattenArrayCheck failure! L * M != N"][(!Self::REQUIREMENT) as usize];

    const __ASSERT_X: usize = Self::REQUIREMENT as usize - 1;
}

impl<T, const L: usize, const M: usize, const N: usize> FlattenArrayCheck<L, M, N> for [[T; L]; M] {}
impl<T, const L: usize, const M: usize, const N: usize> FlattenArrayCheck<L, M, N>
    for &[[T; L]; M]
{
}
impl<T, const L: usize, const M: usize, const N: usize> FlattenArrayCheck<L, M, N>
    for &mut [[T; L]; M]
{
}

impl<T, const L: usize, const M: usize, const N: usize> FlattenArray<T, L, M, N> for [[T; L]; M] {
    fn flatten_array(&self) -> &[T; N] {
        // assert_eq!(L * M, N);
        debug_assert_eq!(L * M, N); // checked at compiled time with FlattenArrayCheck:
        let _ = <Self as FlattenArrayCheck<L, M, N>>::__ASSERT;

        // Safety: size is checked above
        #[allow(unsafe_code)]
        unsafe {
            &*(self.as_ptr() as *const _)
        }
    }
}

impl<T, const L: usize, const M: usize, const N: usize> FlattenArray<T, L, M, N> for &[[T; L]; M] {
    fn flatten_array(&self) -> &[T; N] {
        // assert_eq!(L * M, N);
        debug_assert_eq!(L * M, N); // checked at compiled time with FlattenArrayCheck:
        let _ = <Self as FlattenArrayCheck<L, M, N>>::__ASSERT;

        // Safety: size is checked above
        #[allow(unsafe_code)]
        unsafe {
            &*(self.as_ptr() as *const _)
        }
    }
}

impl<T, const L: usize, const M: usize, const N: usize> FlattenArrayMut<T, L, M, N>
    for &mut [[T; L]; M]
{
    fn flatten_array_mut(&mut self) -> &mut [T; N] {
        // assert_eq!(L * M, N);
        debug_assert_eq!(L * M, N); // checked at compiled time with FlattenArrayCheck:
        let _ = <Self as FlattenArrayCheck<L, M, N>>::__ASSERT;

        // Safety: size is checked above
        #[allow(unsafe_code)]
        unsafe {
            &mut *(self.as_mut_ptr() as *mut _)
        }
    }
}

pub trait FlattenSlice<'a, T, const L: usize> {
    fn flatten_slice(&'a self) -> &'a [T];
}
pub trait FlattenSliceMut<'a, T, const L: usize> {
    fn flatten_slice_mut(&'a mut self) -> &'a mut [T];
}

impl<'a, T: 'a, const L: usize> FlattenSlice<'a, T, L> for &'a [[T; L]] {
    fn flatten_slice(&'a self) -> &'a [T] {
        // Safety: self is a slice of arrays each L elements (of type T), self.len() * L elements in total
        // generated slice is the exact same length (self.len() * L) and same type (T) as the original slice.
        #[allow(unsafe_code)]
        unsafe {
            core::slice::from_raw_parts(self.as_ptr() as *const _, self.len() * L)
        }
    }
}

impl<'a, T: 'a, const L: usize, const M: usize> FlattenSlice<'a, T, L> for [[T; L]; M] {
    fn flatten_slice(&'a self) -> &'a [T] {
        // Safety: self is a slice of arrays each L elements (of type T), M * L elements in total
        // generated slice is the exact same length (M * L) and same type (T) as the original slice.
        #[allow(unsafe_code)]
        unsafe {
            core::slice::from_raw_parts(self.as_ptr() as *const _, M * L)
        }
    }
}

impl<'a, T: 'a, const L: usize, const M: usize, const X: usize> FlattenSlice<'a, T, L> for [[[T; L]; M]; X] {
    fn flatten_slice(&'a self) -> &'a [T] {
        // Safety: self is a slice of arrays each L elements (of type T), M * L elements in total
        // generated slice is the exact same length (M * L) and same type (T) as the original slice.
        #[allow(unsafe_code)]
        unsafe {
            core::slice::from_raw_parts(self.as_ptr() as *const _, X * M * L)
        }
    }
}



impl<'a, T: 'a, const L: usize, const M: usize> FlattenSliceMut<'a, T, L> for [[T; L]; M] {
    fn flatten_slice_mut(&'a mut self) -> &'a mut [T] {
        // Safety: self is a slice of arrays each L elements (of type T), M * L elements in total
        // generated slice is the exact same length (M * L) and same type (T) as the original slice.
        #[allow(unsafe_code)]
        unsafe {
            core::slice::from_raw_parts_mut(self.as_mut_ptr() as *mut _, M * L)
        }
    }
}