use core::ops::{AddAssign, Index, IndexMut};

use rand::{CryptoRng, RngCore};

use crate::{
    poly::{
        dilithium::DilithiumPoly,
        kyber::{KyberPoly, KYBER_POLYBYTES},
        UNIFORM_SEED_BYTES,
    },
};

use super::poly::Polynomial;

#[derive(Debug, Clone, Copy)]
pub struct PolyVec<P, const N: usize, const K: usize>([P; K])
where
    P: Polynomial<N>;

impl<P, const N: usize, const K: usize> Default for PolyVec<P, N, K>
where
    P: Polynomial<N>,
{
    fn default() -> Self {
        PolyVec([P::default(); K])
    }
}

impl<P, const N: usize, const K: usize> Index<usize> for PolyVec<P, N, K>
where
    P: Polynomial<N>,
{
    type Output = P;
    fn index<'a>(&'a self, i: usize) -> &'a Self::Output {
        &self.0[i]
    }
}

impl<P, const N: usize, const K: usize> IndexMut<usize> for PolyVec<P, N, K>
where
    P: Polynomial<N>,
{
    fn index_mut<'a>(&'a mut self, i: usize) -> &'a mut Self::Output {
        &mut self.0[i]
    }
}

impl<P, const N: usize, const K: usize> AsRef<[P; K]> for PolyVec<P, N, K>
where
    P: Polynomial<N>,
{
    #[inline(always)]
    fn as_ref(&self) -> &[P; K] {
        &self.0
    }
}

impl<P, const N: usize, const K: usize> AsMut<[P; K]> for PolyVec<P, N, K>
where
    P: Polynomial<N>,
{
    #[inline(always)]
    fn as_mut(&mut self) -> &mut [P; K] {
        &mut self.0
    }
}

impl<P, const N: usize, const K: usize> PolyVec<P, N, K>
where
    P: Polynomial<N>,
{
    pub fn ntt(&mut self) {
        for poly in self.0.iter_mut() {
            poly.ntt();
        }
    }

    pub fn ntt_and_reduce(&mut self) {
        for poly in self.0.iter_mut() {
            poly.ntt();
            poly.reduce();
        }
    }

    pub fn invntt_tomont(&mut self) {
        for poly in self.0.iter_mut() {
            poly.inv_ntt();
        }
    }

    pub fn reduce(&mut self) {
        for poly in self.0.iter_mut() {
            poly.reduce();
        }
    }

    #[inline]
    pub fn uniform<const TRANSPOSED: bool>(&mut self, seed: &[u8; UNIFORM_SEED_BYTES], i: u8) {
        for (j, poly) in self.as_mut().iter_mut().enumerate() {
            if TRANSPOSED {
                poly.uniform(seed, i, j as u8);
            } else {
                poly.uniform(seed, j as u8, i);
            }
        }
    }

    //     pub fn add_assign(&mut self, other: &Self) {
    //         for i in 0..K {
    //             self[i].add_assign(&other[i]);
    //         }
    //     }

    //     pub fn reduce(&mut self) {
    //         for i in 0..K {
    //             self[i].reduce();
    //         }
    //     }

    //     #[inline]
    //     fn compress_2_or_3(self, r: &mut [u8]) {
    //         const RATIO: usize = 10;
    //         const GCD: usize = 2;
    //         const RATIO_1: usize = RATIO / GCD;
    //         const N: usize = 8 / GCD;
    //         let mut idx = 0;
    //         for i in 0..K {
    //             for j in 0..KYBER_N / N {
    //                 let mut t = [0u16; N];
    //                 for k in 0..N {
    //                     let mut tmp = self[i][4 * j + k];
    //                     let is_negative = (tmp as i16) >> 15;
    //                     tmp += is_negative & KYBER_Q as i16; // if tmp < 0 then tmp += Q (in constant time)
    //                     t[k] = (((((tmp as u32) << RATIO) + (KYBER_Q / 2) as u32) / KYBER_Q as u32)
    //                         & 0x3ff) as u16;
    //                 }
    //                 r[idx + 0] = (t[0] >> 0) as u8;
    //                 r[idx + 1] = ((t[0] >> 8) | (t[1] << 2)) as u8;
    //                 r[idx + 2] = ((t[1] >> 6) | (t[2] << 4)) as u8;
    //                 r[idx + 3] = ((t[2] >> 4) | (t[3] << 6)) as u8;
    //                 r[idx + 4] = (t[3] >> 2) as u8;
    //                 idx += RATIO_1;
    //             }
    //         }
    //     }

    //     #[inline]
    //     fn compress_4(self, r: &mut [u8]) {
    //         let mut idx = 0;
    //         const RATIO: usize = 11;
    //         for i in 0..K {
    //             for j in 0..KYBER_N / 8 {
    //                 let mut t = [0u16; 8];
    //                 for k in 0..8 {
    //                     let mut tmp = self[i][8 * j + k];
    //                     let is_negative = (tmp as i16) >> 15;
    //                     tmp += is_negative & KYBER_Q as i16; // if tmp < 0 then tmp += Q (in constant time)
    //                     t[k] = (((((tmp as u32) << RATIO) + (KYBER_Q / 2) as u32) / KYBER_Q as u32)
    //                         & 0x7ff) as u16;
    //                 }
    //                 // pack 8 x 11 bit values to 11 bytes
    //                 r[idx + 0] = (t[0] >> 0) as u8;
    //                 r[idx + 1] = ((t[0] >> 8) | (t[1] << 3)) as u8;
    //                 r[idx + 2] = ((t[1] >> 5) | (t[2] << 6)) as u8;
    //                 r[idx + 3] = (t[2] >> 2) as u8;
    //                 r[idx + 4] = ((t[2] >> 10) | (t[3] << 1)) as u8;
    //                 r[idx + 5] = ((t[3] >> 7) | (t[4] << 4)) as u8;
    //                 r[idx + 6] = ((t[4] >> 4) | (t[5] << 7)) as u8;
    //                 r[idx + 7] = (t[5] >> 1) as u8;
    //                 r[idx + 8] = ((t[5] >> 9) | (t[6] << 2)) as u8;
    //                 r[idx + 9] = ((t[6] >> 6) | (t[7] << 5)) as u8;
    //                 r[idx + 10] = (t[7] >> 3) as u8;
    //                 idx += RATIO;
    //             }
    //         }
    //     }

    //     pub fn compress_to(self, r: &mut [u8]) {
    //         match K {
    //             2 | 3 => self.compress_2_or_3(r),
    //             _ => self.compress_4(r),
    //         }
    //     }

    //     #[inline(always)]
    //     pub fn basemul_acc(&self, other: &Self, r: &mut Poly<T, N>) {
    //         // TODO: optimize
    //         let mut tmp = Poly::default();
    //         self[0].basemul_montgomery(&other[0], r);

    //         for i in 1..K {
    //             self[i].basemul_montgomery(&other[i], &mut tmp);
    //             *r += &tmp;
    //         }

    //         r.reduce();
    //     }

    //     #[inline(always)]
    //     pub fn to_mont(&mut self) {
    //         for i in 0..K {
    //             self[i].to_mont();
    //         }
    //     }
}

impl<P, const N: usize, const K: usize> AddAssign<&Self> for PolyVec<P, N, K>
where
    P: Polynomial<N>,
{
    fn add_assign(&mut self, rhs: &Self) {
        for i in 0..K {
            self[i] += &rhs[i];
        }
    }
}

// impl<P, const N: usize, const K: usize> Mul<&Self> for PolyVec<P, N, K> {
//     type Output = Poly<T, N>;

//     #[inline(always)]
//     fn mul(self, other: &Self) -> Self::Output {
//         let mut r = Poly::default();
//         self.basemul_acc(other, &mut r);
//         r
//     }
// }

// impl PolyVec<2> {
//     // pub fn compress_to(self, r: &mut [u8]) {
//     //     self.compress_2_or_3(r)
//     // }
// }
// impl PolyVec<3> {
//     // pub fn compress_to(self, r: &mut [u8]) {
//     //     self.compress_2_or_3(r)
//     // }
// }

// impl PolyVec<4> {
//     // pub fn compress_to(self, r: &mut [u8]) {
//     //     self.compress_4(r)
//     // }
// }

// impl PolyVec<2> {
//     const fn K() -> usize {2}
//     pub fn to_bytes(&self) -> [u8;Self::K() * KYBER_POLYBYTES] {
//         let mut r = [0u8;Self::K() * KYBER_POLYBYTES];
//         for i in 0..self.vec.len() {
//             poly_tobytes(&mut r[i*KYBER_POLYBYTES..], self[i]);
//         }
//         r
//     }
// }

// impl PolyVec<3> {
//     const fn K() -> usize {3}
//     pub fn to_bytes(&self) -> [u8;self.vec.len() * KYBER_POLYBYTES] {
//         let mut r = [0u8;Self::K() * KYBER_POLYBYTES];
//         for i in 0..self.vec.len() {
//             poly_tobytes(&mut r[i*KYBER_POLYBYTES..], self[i]);
//         }
//         r
//     }
// }

// impl PolyVec<4> {
//     const fn K() -> usize {3}
//     pub fn to_bytes(&self) -> [u8;Self::K() * KYBER_POLYBYTES] {
//         let mut r = [0u8;Self::K() * KYBER_POLYBYTES];
//         for i in 0..self.vec.len() {
//             poly_tobytes(&mut r[i*KYBER_POLYBYTES..], self[i]);
//         }
//         r
//     }
// }

impl<const K: usize> PolyVec<KyberPoly, { KyberPoly::N }, K> {
    pub fn from_bytes(bytes: &[[u8; KYBER_POLYBYTES]; K]) -> Self {
        let mut pv = PolyVec::<KyberPoly, { KyberPoly::N }, K>::default();
        for i in 0..K {
            pv[i].from_bytes(&bytes[i]);
        }
        pv
    }

    pub fn to_bytes(&self, r: &mut [[u8; KYBER_POLYBYTES]; K]) {
        for i in 0..K {
            self[i].to_bytes(&mut r[i]);
        }
    }
}
pub type KyberPolyVec<const K: usize> = PolyVec<KyberPoly, { KyberPoly::N }, K>;

impl<const K: usize> KyberPolyVec<K> {
    #[doc(hidden)]
    pub fn new_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut pv = KyberPolyVec::<K>::default();
        for i in 0..K {
            pv[i] = KyberPoly::new_random(rng);
        }
        pv
    }
}

pub type DilithiumPolyVec<const K: usize> = PolyVec<DilithiumPoly, { DilithiumPoly::N }, K>;

impl<const K: usize> DilithiumPolyVec<K> {
    pub fn new_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut pv = DilithiumPolyVec::<K>::default();
        for i in 0..K {
            pv[i] = DilithiumPoly::new_random(rng);
        }
        pv
    }
}
