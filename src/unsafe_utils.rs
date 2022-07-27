use crate::params::KYBER_SSBYTES;

// pub fn encode_hex(bytes: &[u8]) -> String {
//     let mut output = String::new();
//     for b in bytes {
//         output.push_str(&format!("{:02x}", b));
//     }
//     output
// }

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

pub(crate) trait SplitArray<T, const N: usize> {
    fn split<const N1: usize, const N2: usize>(&self) -> (&[T; N1], &[T; N2]);
}

pub(crate) trait SplitArrayMut<T, const N: usize> {
    fn split_mut<const N1: usize, const N2: usize>(&mut self) -> (&mut [T; N1], &mut [T; N2]);
}

impl<T, const N: usize> SplitArray<T, N> for [T; N] {
    #[allow(unsafe_code)]
    fn split<const N1: usize, const N2: usize>(&self) -> (&[T; N1], &[T; N2]) {
        assert!(N1 + N2 == N);
        let (s1, s2) = unsafe { (self.get_unchecked(..N1), self.get_unchecked(N1..)) };
        let ptr1 = s1.as_ptr() as *const [T; N1];
        let ptr2 = s2.as_ptr() as *const [T; N2];
        unsafe { (&*ptr1, &*ptr2) }
    }
}

impl<T, const N: usize> SplitArray<T, N> for &[T; N] {
    #[allow(unsafe_code)]

    fn split<const N1: usize, const N2: usize>(&self) -> (&[T; N1], &[T; N2]) {
        assert!(N1 + N2 == N);

        let (s1, s2) = unsafe { (self.get_unchecked(..N1), self.get_unchecked(N1..)) };
        let ptr1 = s1.as_ptr() as *const [T; N1];
        let ptr2 = s2.as_ptr() as *const [T; N2];

        unsafe { (&*ptr1, &*ptr2) }
    }
}

impl<T, const N: usize> SplitArrayMut<T, N> for [T; N] {
    #[allow(unsafe_code)]
    fn split_mut<const N1: usize, const N2: usize>(&mut self) -> (&mut [T; N1], &mut [T; N2]) {
        assert!(N1 + N2 == N);
        let (s1, s2) = unsafe { (self.get_unchecked(..N1), self.get_unchecked(N1..)) };
        let ptr1 = s1.as_ptr() as *mut [T; N1];
        let ptr2 = s2.as_ptr() as *mut [T; N2];
        unsafe { (&mut *ptr1, &mut *ptr2) }
    }
}

impl<T, const N: usize> SplitArrayMut<T, N> for &mut [T; N] {
    #[allow(unsafe_code)]
    fn split_mut<const N1: usize, const N2: usize>(&mut self) -> (&mut [T; N1], &mut [T; N2]) {
        assert!(N1 + N2 == N);
        let (s1, s2) = unsafe { (self.get_unchecked(..N1), self.get_unchecked(N1..)) };
        let ptr1 = s1.as_ptr() as *mut [T; N1];
        let ptr2 = s2.as_ptr() as *mut [T; N2];
        unsafe { (&mut *ptr1, &mut *ptr2) }
    }
}

#[derive(Debug)]
pub enum KyberError {
    DecapsFailure, // Re-encapsulated message did not match provided ciphertex. Most probably an invalid ciphertext. Returned by decap.
    RngFailure, // was not able to retrieve required random from RNG. Returned by encap and keypair.
}

