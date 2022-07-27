use crate::field::kyber::{fqmul, KyberFq, MONT};

use crate::field::{kyber::KYBER_Q, *};
use crate::keccak::fips202::Shake128Params;
use crate::keccak::KeccakParams;
use crate::utils::split::*;

use super::{Poly, Polynomial};

pub const KYBER_N: usize = 256;

const ROOT_OF_UNITY: i16 = 17; // 2Nth (256-th) root of 1 mod Q

pub type KyberPoly = Poly<KyberFq, { KYBER_N / 2 }>;

pub const KYBER_POLYBYTES: usize = { KyberPoly::N } * 3;

const ZETAS: [i16; KyberPoly::N - 1] = {
    let mut zetas = [0i16; KyberPoly::N - 1];
    let mut i = 1;
    let mut omega = MONT;
    const ROOT_OF_UNITY_MONT: i16 = (MONT * ROOT_OF_UNITY) % KYBER_Q;
    while i < KyberPoly::N {
        let br = (i as u8).reverse_bits() as usize >> 1;
        omega = fqmul(omega, ROOT_OF_UNITY_MONT); //((omega as i32 * ROOT_OF_UNITY as i32) % KYBER_Q as i32) as i16;
        zetas[br - 1] = omega;
        i += 1;
    }
    zetas
};

impl Polynomial<{ KYBER_N / 2 }> for KyberPoly {
    type F = KyberFq;

    const INV_NTT_SCALE: <Self::F as Field>::E = 1441; // 512 to convert to non-mongomery form

    #[inline(always)]
    fn zetas(k: usize) -> <Self::F as Field>::E {
        ZETAS[k]
    }

    fn pointwise(&self, other: &Self, result: &mut Self) {
        for (((tr, ta), tb), zeta) in result
            .as_mut()
            .into_array_chunks_mut::<2>()
            .zip(self.as_ref().into_array_chunks_iter::<2>())
            .zip(other.as_ref().into_array_chunks_iter::<2>())
            .zip(ZETAS[63..].iter())
        {
            tr[0] = ta[0].basemul(tb[0], *zeta);
            tr[1] = ta[1].basemul(tb[1], -*zeta);
        }
    }

    fn rej_uniform(&mut self, mut ctr: usize, bytes: &[u8; Shake128Params::RATE_BYTES]) -> usize {
        debug_assert!(ctr < KYBER_N);
        debug_assert!(Shake128Params::RATE_BYTES % 3 == 0);

        // TODO compare performance vs safe
        let p: &mut [i16; KYBER_N] = self.as_scalar_array_mut();

        for buf in bytes.chunks_exact(3) {
            // TODO compare with iterator
            if ctr >= KYBER_N {
                break;
            }
            let val0 = ((buf[0] >> 0) as u16 | (buf[1] as u16) << 8) & 0xFFF;
            if val0 < KYBER_Q as u16 {
                p[ctr] = val0 as i16;
                ctr += 1;
            }

            if ctr >= KYBER_N {
                break;
            }
            let val1 = ((buf[1] >> 4) as u16 | (buf[2] as u16) << 4) & 0xFFF;
            if val1 < KYBER_Q as u16 {
                p[ctr] = val1 as i16;
                ctr += 1;
            }
        }
        ctr
    }
}

impl KyberPoly {
    pub fn to_bytes(&self, bytes: &mut [u8; KYBER_POLYBYTES]) {
        for (f, r) in self.as_ref().iter().zip(bytes.into_array_chunks_mut::<3>()) {
            // map to positive standard representatives
            let f = f.freeze();
            let [t0, t1] = f.0;
            r[0] = t0 as u8;
            r[1] = ((t0 >> 8) | (t1 << 4)) as u8;
            r[2] = (t1 >> 4) as u8;
        }
    }

    pub fn from_bytes(&mut self, bytes: &[u8]) {
        for (f, a) in self
            .as_mut()
            .iter_mut()
            .zip(bytes.into_array_chunks_iter::<3>())
        {
            f.0 = [
                ((a[0] >> 0) as u16 | ((a[1] as u16) << 8) & 0xFFF) as i16,
                ((a[1] >> 4) as u16 | ((a[2] as u16) << 4) & 0xFFF) as i16,
            ];
        }
    }

    pub fn cbd2(&mut self, buf: &[u8; KYBER_N / 2]) {
        const MASK55: u32 = 0x55_55_55_55;
        const MASK33: u32 = 0x33333333;
        const MASK03: u32 = 0x03030303;
        const MASK0F: u32 = 0x0F0F0F0F;

        for (r, bytes) in self
            .as_mut()
            .into_array_chunks_mut::<4>()
            .zip(buf.into_array_chunks_iter::<4>())
        {
            let t = u32::from_le_bytes(*bytes);
            let d: u32 = (t & MASK55) + ((t >> 1) & MASK55);
            let e = (d & MASK33) + MASK33 - ((d >> 2) & MASK33);
            let f0 = (e & MASK0F) - MASK03;
            let f1 = ((e >> 4) & MASK0F) - MASK03;
            for j in 0..4 {
                let a = ((d >> (8 * j)) & 0x3) as i16;
                let b = ((d >> (8 * j + 2)) & 0x3) as i16;
                r[j].0[0] = a - b;

                let a = ((d >> (8 * j + 3)) & 0x3) as i16;
                let b = ((d >> (8 * j + 4)) & 0x3) as i16;
                r[j].0[1] = a - b;
            }
        }
    }

    pub fn cbd3(&mut self, buf: &[u8; 3 * KYBER_N / 4]) {
        const MASK249: u32 = 0x00249249; // 0b001..001001

        #[inline]
        fn load24_littleendian(x: [u8; 3]) -> u32 {
            let mut r = x[0] as u32;
            r |= (x[1] as u32) << 8;
            r |= (x[2] as u32) << 16;
            r
        }

        for (r, bytes) in self
            .as_mut()
            .into_array_chunks_mut::<2>()
            .zip(buf.into_array_chunks_iter::<3>())
        {
            let t = load24_littleendian(*bytes);
            let mut d = t & MASK249;
            d += (t >> 1) & MASK249;
            d += (t >> 2) & MASK249;

            for c in r {
                let a = d as i16 & 0x7;
                d >>= 3;
                let b = d as i16 & 0x7;
                d >>= 3;
                c.0[0] = a - b;

                let a = d as i16 & 0x7;
                d >>= 3;
                let b = d as i16 & 0x7;
                d >>= 3;
                c.0[1] = a - b;
            }
        }
    }

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

    #[inline(always)]
    pub fn ntt_and_reduce(&mut self) {
        self.ntt();
        self.reduce();
    }

    pub fn into_array(&self) -> [<KyberFq as Field>::E; KYBER_N] {
        array_init::array_init(|i: usize| self[i / 2].0[i % 2])
    }

    pub fn as_scalar_array_mut(&mut self) -> &mut [<KyberFq as Field>::E; KYBER_N] {
        #[allow(unsafe_code)]
        unsafe {
            core::mem::transmute(self.as_mut())
        }
    }

    //
    //
    //
    //
    // fn compress_to<const KYBER_K: usize>(&self, r: &mut [u8]) {
    //     let mut t = [0u8; 8];
    //     let mut k = 0usize;
    //     let mut u: i16;

    //     match KYBER_K {
    //         2 | 3 => {
    //             for i in 0..N / 8 {
    //                 for j in 0..8 {
    //                     // map to positive standard representatives
    //                     u = self[8 * i + j];
    //                     u += (u >> 15) & KYBER_Q as i16;
    //                     t[j] = (((((u as u16) << 4) + KYBER_Q as u16 / 2) / KYBER_Q as u16) & 15)
    //                         as u8;
    //                 }
    //                 r[k] = t[0] | (t[1] << 4);
    //                 r[k + 1] = t[2] | (t[3] << 4);
    //                 r[k + 2] = t[4] | (t[5] << 4);
    //                 r[k + 3] = t[6] | (t[7] << 4);
    //                 k += 4;
    //             }
    //         }
    //         _ => {
    //             // 4
    //             for i in 0..(N / 8) {
    //                 for j in 0..8 {
    //                     // map to positive standard representatives
    //                     u = self.0[8 * i + j];
    //                     u += (u >> 15) & KYBER_Q as i16;
    //                     t[j] = (((((u as u32) << 5) + KYBER_Q as u32 / 2) / KYBER_Q as u32) & 31)
    //                         as u8;
    //                 }
    //                 r[k] = t[0] | (t[1] << 5);
    //                 r[k + 1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
    //                 r[k + 2] = (t[3] >> 1) | (t[4] << 4);
    //                 r[k + 3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
    //                 r[k + 4] = (t[6] >> 2) | (t[7] << 3);
    //                 k += 5;
    //             }
    //         }
    //     }
    // }

    // fn decompress<const KYBER_K: usize>(&mut self, a: &[u8]) {
    //     match KYBER_K {
    //         2 | 3 => {
    //             let mut idx = 0usize;
    //             for i in 0..N / 2 {
    //                 self.0[2 * i + 0] =
    //                     ((((a[idx] & 15) as usize * KYBER_Q as usize) + 8) >> 4) as i16;
    //                 self.0[2 * i + 1] =
    //                     ((((a[idx] >> 4) as usize * KYBER_Q as usize) + 8) >> 4) as i16;
    //                 idx += 1;
    //             }
    //         }
    //         _ => {
    //             // 4
    //             let mut idx = 0usize;
    //             let mut t = [0u8; 8];
    //             for i in 0..N / 8 {
    //                 t[0] = a[idx + 0];
    //                 t[1] = (a[idx + 0] >> 5) | (a[idx + 1] << 3);
    //                 t[2] = a[idx + 1] >> 2;
    //                 t[3] = (a[idx + 1] >> 7) | (a[idx + 2] << 1);
    //                 t[4] = (a[idx + 2] >> 4) | (a[idx + 3] << 4);
    //                 t[5] = a[idx + 3] >> 1;
    //                 t[6] = (a[idx + 3] >> 6) | (a[idx + 4] << 2);
    //                 t[7] = a[idx + 4] >> 3;
    //                 idx += 5;
    //                 for j in 0..8 {
    //                     self.0[8 * i + j] =
    //                         ((((t[j] as u32) & 31) * KYBER_Q as u32 + 16) >> 5) as i16;
    //                 }
    //             }
    //         }
    //     }
    // }

    // fn frommont(&mut self) {
    //     let f = ((1u64 << 32) % KYBER_Q as u64) as i16;
    //     for i in 0..N {
    //         let a = self.0[i] as i32 * f as i32;
    //         self.0[i] = montgomery_reduce(a);
    //     }
    // }

    // fn from_message(msg: &[u8]) -> Self {
    //     let mut poly = Poly::default();
    //     let mut mask;
    //     for i in 0..KYBER_SYMBYTES {
    //         for j in 0..8 {
    //             mask = ((msg[i] as u16 >> j) & 1).wrapping_neg();
    //             poly.0[8 * i + j] = (mask & ((KYBER_Q + 1) / 2) as u16) as i16;
    //         }
    //     }
    //     poly
    // }

    // fn tomsg(&self, msg: &mut [u8]) {
    //     let mut t;

    //     for i in 0..KYBER_SYMBYTES {
    //         msg[i] = 0;
    //         for j in 0..8 {
    //             t = self.0[8 * i + j];
    //             t += (t >> 15) & KYBER_Q as i16;
    //             t = (((t << 1) + KYBER_Q as i16 / 2) / KYBER_Q as i16) & 1;
    //             msg[i] |= (t << j) as u8;
    //         }
    //     }
    // }
    // /// Inplace conversion of all coefficients of a polynomial from normal domain to Montgomery domain
    // /// # Arguments
    // /// * `r` - Input/output polynomial
    // fn to_mont(&mut self) {
    //     const F: i16 = ((1u64 << 32) % KYBER_Q as u64) as i16;
    //     for i in 0..N {
    //         self.0[i] = montgomery_reduce(self.0[i] as i32 * F as i32);
    //     }
    // }
}

use rand::{CryptoRng, Rng, RngCore};

impl KyberPoly {
    #[doc(hidden)]
    pub fn new_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut poly = Self::default();
        fn frand<R: RngCore + CryptoRng>(rng: &mut R) -> i16 {
            rng.gen_range(-KYBER_Q / 2..=KYBER_Q / 2)
            // rng.gen_range(-KYBER_Q..=KYBER_Q)
        }
        for c in poly.as_mut() {
            c.0[0] = frand(rng);
            c.0[1] = frand(rng);
        }
        poly
    }
}

#[cfg(test)]
mod tests {
    use crate::field::kyber::KYBER_Q;
    use crate::utils::*;

    use super::*;

    #[test]
    fn q_inv_test() {
        assert_eq!(kyber::QINV, invm(KYBER_Q as i32, 1 << 16).unwrap() as i16,);
    }

    #[test]
    fn test_ntt_and_then_invtt() {
        let mut rng = rand::thread_rng();
        for testcase in 0..3_000 {
            let mut poly = KyberPoly::new_random(&mut rng);
            let poly_copy = poly.clone();
            poly.ntt();
            poly.inv_ntt();

            for f in poly.as_mut() {
                *f = *f * 1; // * R^-1
            }
            // poly.reduce();

            assert_eq!(poly, poly_copy, "failed testcase #{}", testcase);
        }
    }

    // #[test]
    // fn test_ntt_and_then_invtt_ref() {
    //     for testcase in 1..1000 {
    //         let mut poly = Poly::new_random();
    //         let poly_copy = poly.clone();
    //         cref::ntt(&mut poly.0);
    //         cref::invntt(&mut poly.0);
    //         assert_eq!(poly, poly_copy, "failed testcase #{}", testcase);
    //     }
    // }

    #[test]
    fn test_ntt_vs_ref() {
        let mut rng = rand::thread_rng();
        for testcase in 0..3_000 {
            let mut poly = KyberPoly::new_random(&mut rng);
            // println!("poly before ntt: {:?}", poly);
            let mut p = [0i16; { KYBER_N }];
            for i in 0..KYBER_N / 2 {
                p[2 * i] = poly[i].0[0];
                p[2 * i + 1] = poly[i].0[1];
            }
            poly.ntt();
            poly.reduce();
            // println!("poly after ntt: {:?}", poly);
            // println!("p before ntt: {:?}", p);
            crystals_cref::kyber::ntt(&mut p);

            for i in 0..KYBER_N / 2 {
                assert_eq!(p[2 * i], poly[i].0[0]);
                assert_eq!(p[2 * i + 1], poly[i].0[1]);
            }
            // assert_eq!(poly., poly_copy, "failed testcase #{}", testcase);
        }
    }

    #[test]
    fn test_invntt_vs_ref() {
        let mut rng = rand::thread_rng();
        for _ in 0..3_000 {
            let mut poly = KyberPoly::new_random(&mut rng);
            let mut p = poly.into_array();
            poly.inv_ntt();
            poly.reduce();
            crystals_cref::kyber::inv_ntt(&mut p);
            crystals_cref::kyber::poly_reduce(&mut p);

            assert_eq!(p, poly.into_array());
        }
    }

    #[test]
    fn pwm_vs_ref() {
        let mut rng = rand::thread_rng();
        for _ in 0..1_000 {
            let poly_a = KyberPoly::new_random(&mut rng);
            let poly_b = KyberPoly::new_random(&mut rng);
            let mut poly_r = KyberPoly::default();

            let a = poly_a.into_array();
            let b = poly_b.into_array();
            let mut r = poly_r.into_array();

            poly_a.pointwise(&poly_b, &mut poly_r);
            poly_r.reduce();

            crystals_cref::kyber::poly_pointwise_montgomery(&mut r, &a, &b);
            crystals_cref::kyber::poly_reduce(&mut r);

            assert_eq!(r, poly_r.into_array());
        }
    }
}
