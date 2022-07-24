use core::fmt::Debug;
use core::ops::{Add, AddAssign, Index, IndexMut, Sub, SubAssign};
use core::slice::{Iter, IterMut};

use crate::field::*;

pub mod dilithium;
pub mod kyber;

pub trait Polynomial<const N: usize>:
    Index<usize, Output = Self::F>
    + IntoIterator
    + IndexMut<usize, Output = Self::F>
    + AsRef<[Self::F; N]>
    + AsMut<[Self::F; N]>
    + Default
    + Sized
    + Clone
    + Copy
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + for<'a> AddAssign<&'a Self>
    + for<'a> SubAssign<&'a Self>
{
    type F: Field;

    const N: usize = N;

    const INV_NTT_SCALE: <Self::F as Field>::E;

    fn zetas(k: usize) -> <Self::F as Field>::E;

    // Lessons learnt from benchmarking:
    // - Iterator::step_by is _VERY_ slow!
    // - Rust (checked) array indexing is slow. Use iterators where possible.
    //

    // this is the cleaner version, but > %60 slower!
    // fn ntt(&mut self) {
    //     let mut k = 0;
    //     let mut len = Self::N / 2;
    //     while len > 0 {
    //         for start in (0..Self::N).step_by(len << 1) {
    //             let zeta = Self::zetas(k);
    //             k += 1;
    //             for j in start..(start + len) {
    //                 let (u, v) = (self[j], self[j + len]);
    //                 let t = v * zeta;
    //                 self[j] = u + t;
    //                 self[j + len] = u - t;
    //             }
    //         }
    //         len >>= 1;
    //     }
    // }

    // this seems to be one less "<< 1" operation but is actually > 3% slower for Kyber:
    // let mut len = Self::N;
    // loop {
    //     let len_times_two = len;
    //     len >>= 1; // moved from bottom of the loop
    //     if len == 0 {
    //         break;
    //     }
    //   ...
    // }

    fn ntt(&mut self) {
        let mut k = 0;
        let mut len = Self::N / 2;
        while len > 0 {
            let len_times_two = len << 1;
            let mut start = 0;
            while start < Self::N {
                let zeta = Self::zetas(k);
                k += 1;
                let end = start + len_times_two;
                let (top, bottom) = self.as_mut()[start..end].split_at_mut(len);

                // u and v are len apart
                for (u, v) in top.iter_mut().zip(bottom) {
                    let t = *v * zeta;
                    *v = *u - t;
                    *u = *u + t;
                }
                start = end;
            }
            len >>= 1;
        }
    }

    // fn inv_ntt(&mut self) {
    //     let mut k = Self::N - 1;
    //     let mut len = 1; // 2
    //     while len < Self::N {
    //         for start in (0..Self::N).step_by(len << 1) {
    //             k -= 1;
    //             let zeta = Self::zetas(k);
    //             for j in start..(start + len) {
    //                 let (u, v) = (self[j], self[j + len]);
    //                 self[j] = (u + v).maybe_reduce();
    //                 self[j + len] = (v - u) * zeta;
    //             }
    //         }
    //         len <<= 1;
    //     }

    //     for f in self.as_mut() {
    //         *f *= Self::INV_NTT_SCALE;
    //     }
    // }

    fn inv_ntt(&mut self) {
        let mut k = Self::N - 1;
        let mut len = 1;
        while len < Self::N {
            let mut start = 0;
            let len_times_two = len << 1;
            while start < Self::N {
                k -= 1;
                let zeta = Self::zetas(k);
                let end = start + len_times_two;
                let (left, right) = self.as_mut()[start..end].split_at_mut(len);

                for (u, v) in left.iter_mut().zip(right) {
                    let t = *u;
                    *u = (t + *v).maybe_reduce();
                    *v = (*v - t) * zeta;
                }
                start = end;
            }
            len = len_times_two;
        }

        for f in self.as_mut() {
            *f *= Self::INV_NTT_SCALE;
        }
    }

    /// Applies Barrett reduction to all coefficients of a polynomial
    /// # Arguments
    /// * `r` - Input/output polynomial
    #[inline]
    fn reduce(&mut self) {
        for f in self.as_mut() {
            *f = f.reduce();
        }
    }

    fn pointwise(&self, other: &Self, result: &mut Self);

    // fn getnoise_eta1<const K: usize, PRF: Prf>(
    //     prf: &mut PRF,
    //     seed: &[u8; KYBER_SYMBYTES],
    //     nonce: u8,
    // ) -> Self {
    //     if K == 2 {
    //         let mut poly = Self::default();
    //         // let mut buf = [0u8; 3 * Self::N / 4]; // TODO avoid double initialization?
    //         // prf.prf(&mut buf, seed, nonce);
    //         // cbd3(&mut poly.0, &buf);
    //         poly
    //     } else {
    //         Self::getnoise_eta2(prf, seed, nonce)
    //     }
    // }

    // fn getnoise_eta2<PRF: Prf>(prf: &mut PRF, seed: &[u8; KYBER_SYMBYTES], nonce: u8) -> Self {
    //     let mut poly = Poly::default();
    //     // let mut buf = [0u8; Self::N / 2]; // TODO avoid double initialization?
    //     // let mut buf = [0u8; 256 / 2]; // FIXME
    //     // prf.prf(&mut buf, seed, nonce);
    //     // cbd2(&mut poly.0, &mut buf);
    //     poly
    // }

    // fn rej_sample(&mut self, buf: &[u8]) -> usize {
    //     let mut ctr = 0;
    //     let mut buf = buf;

    //     while ctr < N && buf.len() >= 3 {
    //         let val0 = ((buf[0] >> 0) as u16 | (buf[1] as u16) << 8) & 0xFFF;
    //         let val1 = ((buf[1] >> 4) as u16 | (buf[2] as u16) << 4) & 0xFFF;
    //         buf = &buf[3..];

    //         if val0 < KYBER_Q as u16 {
    //             self[ctr] = val0 as i16;
    //             ctr += 1;
    //         }
    //         if ctr < N && val1 < KYBER_Q as u16 {
    //             self[ctr] = val1 as i16;
    //             ctr += 1;
    //         }
    //     }
    //     ctr
    // }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Poly<T: Field, const N: usize>([T; N]);

impl<T: Field, const N: usize> Default for Poly<T, N> {
    #[inline(always)]
    fn default() -> Self {
        Poly([T::default(); N])
    }
}

// impl<T: Field, const N: usize> AsRef<[T]> for Poly<T, N> {
//     #[inline(always)]
//     fn as_ref(&self) -> &[T] {
//         &self.0
//     }
// }
// impl<T: Field, const N: usize> AsMut<[T]> for Poly<T, N> {
//     #[inline(always)]
//     fn as_mut(&mut self) -> &mut [T] {
//         &mut self.0
//     }
// }

impl<F: Field, const N: usize> IntoIterator for Poly<F, N> {
    type Item = F;

    type IntoIter = core::array::IntoIter<F, N>;

    #[inline(always)]
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, F: Field, const N: usize> IntoIterator for &'a Poly<F, N> {
    type Item = &'a F;
    type IntoIter = Iter<'a, F>;

    #[inline(always)]
    fn into_iter(self) -> Iter<'a, F> {
        self.0.iter()
    }
}

impl<'a, F: Field, const N: usize> IntoIterator for &'a mut Poly<F, N> {
    type Item = &'a mut F;
    type IntoIter = IterMut<'a, F>;

    #[inline(always)]
    fn into_iter(self) -> IterMut<'a, F> {
        self.0.iter_mut()
    }
}

impl<T: Field, const N: usize> Add<&Self> for Poly<T, N> {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: &Self) -> Self::Output {
        let mut cp = self.clone();
        cp += rhs;
        cp
    }
}
impl<T: Field, const N: usize> Sub<&Self> for Poly<T, N> {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: &Self) -> Self::Output {
        let mut cp = self.clone();
        cp -= rhs;
        cp
    }
}

/// Adds `rhs` polynomial to self; no modular reduction is performed.
/// # Arguments
/// * `rhs` - Righthand-side input polynomial
impl<T: Field, const N: usize> AddAssign<&Self> for Poly<T, N> {
    #[inline(always)]
    fn add_assign(&mut self, rhs: &Self) {
        for i in 0..self.0.len() {
            self[i] += rhs[i];
        }
    }
}

/// Subtracts `rhs` polynomial from self, i.e. `self` <- `self` - `rhs` ; no modular reduction is performed.
/// # Arguments
/// * `rhs` - Righthand-side input polynomial
impl<T: Field, const N: usize> SubAssign<&Self> for Poly<T, N> {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: &Self) {
        for i in 0..self.0.len() {
            self[i] -= rhs[i];
        }
    }
}

impl<T: Field, const N: usize> Index<usize> for Poly<T, N> {
    type Output = T;
    #[inline(always)]
    fn index<'a>(&'a self, i: usize) -> &'a Self::Output {
        &self.0[i]
    }
}

impl<T: Field, const N: usize> IndexMut<usize> for Poly<T, N> {
    #[inline(always)]
    fn index_mut<'a>(&'a mut self, i: usize) -> &'a mut Self::Output {
        &mut self.0[i]
    }
}

impl<F: Field, const N: usize> AsRef<[F; N]> for Poly<F, N> {
    #[inline(always)]
    fn as_ref(&self) -> &[F; N] {
        &self.0
    }
}

impl<F: Field, const N: usize> AsMut<[F; N]> for Poly<F, N> {
    #[inline(always)]
    fn as_mut(&mut self) -> &mut [F; N] {
        &mut self.0
    }
}

impl<F: Field, const N: usize> Poly<F, N> {}
