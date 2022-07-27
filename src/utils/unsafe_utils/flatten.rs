pub trait Flatten<T, const L: usize> {
    fn flatten(&self) -> &[T];
}

impl<T, const L: usize> Flatten<T, L> for [[T; L]] {
    fn flatten(&self) -> &[T] {
        #[allow(unsafe_code)]
        unsafe {
            core::slice::from_raw_parts(self.as_ptr() as *const _, self.len() * L)
        }
    }
}
