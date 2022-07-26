pub mod dilithium;
pub mod kyber;

use crate::field::Field;
use crate::keccak::fips202::{CrystalsXof, Shake128, Shake128Params, SpongeOps};
use crate::keccak::KeccakParams;
use crate::lib::fmt::Debug;
use crate::lib::ops::{AddAssign, Index, IndexMut, SubAssign};
use crate::lib::slice::{Iter, IterMut};
use crate::polyvec::PolyVec;

// TODO use Parameters
pub const UNIFORM_SEED_BYTES: usize = 32;

pub trait Polynomial:
    Index<usize, Output = Self::F>
    + IndexMut<usize, Output = Self::F>
    // + IntoIterator
    + Default
    + Sized
    + Clone
    + Copy // needed for PolyVec::default()
    + for<'a> AddAssign<&'a Self>
    + for<'a> SubAssign<&'a Self>
{
    type F: Field;
}

pub trait SizedPolynomial<const N: usize>:
    Polynomial + AsRef<[Self::F; N]> + AsMut<[Self::F; N]>
{
    const N: usize = N;

    const INV_NTT_SCALE: <Self::F as Field>::E;

    const SCALAR_BYTES: usize = core::mem::size_of::<<Self::F as Field>::E>();

    const UNIFORM_SEED_BYTES: usize = UNIFORM_SEED_BYTES; // not usable for array size

    const NUM_SCALARS: usize =
        Self::N * core::mem::size_of::<Self::F>() / core::mem::size_of::<<Self::F as Field>::E>();

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
                    *u += t;
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
    #[inline(always)]
    fn reduce(&mut self) {
        for f in self.as_mut() {
            *f = f.reduce();
        }
    }

    fn pointwise(&self, other: &Self, result: &mut Self);

    fn pointwise_acc(&self, other: &Self, result: &mut Self);

    fn vector_mul_acc<const K: usize>(
        &mut self,
        lhs: &PolyVec<Self, N, K>,
        rhs: &PolyVec<Self, N, K>,
    ) {
        let mut t = Self::default();

        for (l, r) in lhs.as_ref().iter().zip(rhs.as_ref().iter()) {
            l.pointwise(r, &mut t);
            self.add_assign(&t);
        }
    }

    fn rej_uniform(&mut self, start: usize, bytes: &[u8; Shake128Params::RATE_BYTES]) -> usize;

    #[inline]
    fn uniform(&mut self, seed: &[u8; UNIFORM_SEED_BYTES], i: u8, j: u8) {
        let mut shake128 = Shake128::default();
        shake128.absorb_xof_with_nonces(seed, i, j);
        let mut xof_out = [0u8; Shake128Params::RATE_BYTES];

        let mut ctr = 0;
        while ctr < Self::NUM_SCALARS {
            shake128.squeeze(&mut xof_out);
            ctr = self.rej_uniform(ctr, &xof_out);
        }
        debug_assert_eq!(ctr, Self::NUM_SCALARS);
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Poly<T: Field, const N: usize>([T; N]);

impl<T: Field, const N: usize> Default for Poly<T, N> {
    #[inline(always)]
    fn default() -> Self {
        Poly([T::default(); N])
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

/// Adds `rhs` polynomial to self; no modular reduction is performed.
/// # Arguments
/// * `rhs` - Righthand-side input polynomial
impl<T: Field, const N: usize> AddAssign<&Self> for Poly<T, N> {
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        for (l, r) in self.into_iter().zip(rhs) {
            *l += *r;
        }
    }
}

/// Subtracts `rhs` polynomial from self, i.e. `self` <- `self` - `rhs` ; no modular reduction is performed.
/// # Arguments
/// * `rhs` - Righthand-side input polynomial
impl<T: Field, const N: usize> SubAssign<&Self> for Poly<T, N> {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: &Self) {
        for (left, right) in self.as_mut().iter_mut().zip(rhs) {
            *left -= *right;
        }
    }
}

impl<T: Field, const N: usize> Index<usize> for Poly<T, N> {
    type Output = T;
    #[inline(always)]
    fn index(&self, i: usize) -> &Self::Output {
        &self.0[i]
    }
}

impl<T: Field, const N: usize> IndexMut<usize> for Poly<T, N> {
    #[inline(always)]
    fn index_mut(&mut self, i: usize) -> &mut Self::Output {
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

#[cfg(test)]
mod tests {}
