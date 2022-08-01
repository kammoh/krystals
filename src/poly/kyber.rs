use core::mem::size_of;

use crate::field::kyber::{caddq, fqmul, KyberFq, KYBER_Q, MONT};
use crate::field::Field;
use crate::keccak::fips202::{CrystalsPrf, HasParams, Shake128, Shake256, SpongeOps};
use crate::keccak::KeccakParams;
use crate::lib::mem::transmute;
use crate::utils::flatten::FlattenArray;
use crate::utils::split::*;

use super::{Poly, Polynomial, SizedPolynomial};

pub const KYBER_N: usize = 256;

const ROOT_OF_UNITY: i16 = 17; // 2Nth (256-th) root of 1 mod Q

pub type KyberPoly = Poly<KyberFq, { KYBER_N / 2 }>;

pub const POLYBYTES: usize = { KyberPoly::N } * 3;

pub const MSG_BYTES: usize = 32;

pub const NOISE_SEED_BYTES: usize = 32;

pub type Xof = Shake128;
pub const XOF_BLOCK_BYTES: usize = <Xof as HasParams<_>>::Params::RATE_BYTES;

pub type Prf = Shake256;
pub const PRF_BLOCK_BYTES: usize = <Prf as HasParams<_>>::Params::RATE_BYTES;

pub(crate) const fn poly_compressed_bytes(d: u8) -> usize {
    KYBER_N * d as usize / 8 // == 32 * d
}

pub(crate) const fn poly_compressed_bytes_for_k<const K: usize>() -> usize {
    match K {
        2 | 3 => poly_compressed_bytes(4),
        4 => poly_compressed_bytes(5),
        _ => unreachable!(),
    }
}

pub(crate) const fn polyvec_compressed_bytes_for_k<const K: usize>() -> usize {
    (match K {
        2 | 3 => poly_compressed_bytes(10),
        4 => poly_compressed_bytes(11),
        _ => unreachable!(),
    }) * K
}

pub const fn kyber_ciphertext_bytes<const K: usize>() -> usize {
    polyvec_compressed_bytes_for_k::<K>() + poly_compressed_bytes_for_k::<K>()
}

#[inline(always)]
pub(crate) fn compress_d<const D: usize>(u: i16) -> u16 {
    const Q: u32 = KYBER_Q as u32;
    const HALF_Q: u32 = KYBER_Q as u32 / 2;

    let u = caddq(u) as u32;

    ((((u << D as u8) + HALF_Q) / Q) & ((1 << D as u8) - 1)) as u16
}

#[inline(always)]
pub(crate) fn decompress_d<const D: usize>(u: u16) -> i16 {
    debug_assert!(D <= 16);

    const Q: u32 = KYBER_Q as u32;

    let u = u & ((1 << D) - 1);

    ((u as u32 * Q + (1 << (D - 1))) >> D) as i16
}

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

impl Polynomial for KyberPoly {
    type F = KyberFq;
}

impl SizedPolynomial<{ KYBER_N / 2 }> for KyberPoly {
    const INV_NTT_SCALE: <Self::F as Field>::E = 1441; // 512 to convert to non-mongomery form

    #[inline(always)]
    fn zetas(k: usize) -> <Self::F as Field>::E {
        ZETAS[k]
    }

    fn pointwise(&self, other: &Self, result: &mut Self) {
        for (((tr, ta), tb), zeta) in result
            .as_mut()
            .as_array_chunks_mut::<2>()
            .zip(self.as_ref().as_array_chunks::<2>())
            .zip(other.as_ref().as_array_chunks::<2>())
            .zip(ZETAS[63..].iter())
        {
            tr[0] = ta[0].basemul(tb[0], *zeta);
            tr[1] = ta[1].basemul(tb[1], -*zeta);
        }
    }

    fn rej_uniform(&mut self, mut ctr: usize, bytes: &[u8; XOF_BLOCK_BYTES]) -> usize {
        debug_assert!(ctr < Self::NUM_SCALARS);
        debug_assert!(bytes.len() % 3 == 0);

        // TODO compare performance vs safe
        let p: &mut [i16; Self::NUM_SCALARS] = self.as_scalar_array_mut();

        for buf in bytes.chunks_exact(3) {
            // TODO compare with iterator
            if ctr >= Self::NUM_SCALARS {
                break;
            }
            let val0 = (buf[0] as u16 | (buf[1] as u16) << 8) & 0xFFF;
            if val0 < KYBER_Q as u16 {
                p[ctr] = val0 as i16;
                ctr += 1;
            }

            if ctr >= Self::NUM_SCALARS {
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

    fn pointwise_acc(&self, other: &Self, result: &mut Self) {
        for (((r, a), b), zeta) in result
            .as_mut()
            .as_array_chunks_mut::<2>()
            .zip(self.as_ref().as_array_chunks::<2>())
            .zip(other.as_ref().as_array_chunks::<2>())
            .zip(ZETAS[63..].iter())
        {
            r[0] += a[0].basemul(b[0], *zeta);
            r[1] += a[1].basemul(b[1], -*zeta);
        }
    }
}

impl KyberPoly {
    #[inline]
    pub fn to_bytes(&self, bytes: &mut [u8; POLYBYTES]) {
        for (f, r) in self.as_ref().iter().zip(bytes.as_array_chunks_mut::<3>()) {
            // map to positive standard representatives
            let f = f.freeze();
            let [t0, t1] = f.0;
            r[0] = t0 as u8;
            r[1] = ((t0 >> 8) | (t1 << 4)) as u8;
            r[2] = (t1 >> 4) as u8;
        }
    }

    #[inline]
    pub fn from_bytes(&mut self, bytes: &[u8]) {
        for (f, a) in self.as_mut().iter_mut().zip(bytes.as_array_chunks::<3>()) {
            f.0 = [
                (a[0] as u16 | ((a[1] as u16) << 8) & 0xFFF) as i16,
                ((a[1] >> 4) as u16 | ((a[2] as u16) << 4) & 0xFFF) as i16,
            ];
        }
    }

    #[inline]
    pub fn cbd2(&mut self, buf: &[u8; KYBER_N / 2]) {
        const MASK55: u32 = 0x55_55_55_55;

        for (r, bytes) in self
            .as_mut()
            .as_array_chunks_mut::<4>()
            .zip(buf.as_array_chunks::<4>())
        {
            let t = u32::from_le_bytes(*bytes);

            let f0 = t & MASK55;
            let f1 = (t >> 1) & MASK55;
            let d = f0.wrapping_add(f1);

            for (j, rj) in r.iter_mut().enumerate() {
                let a = ((d >> (8 * j)) & 0x3) as i8;
                let b = ((d >> (8 * j + 2)) & 0x3) as i8;
                rj.0[0] = (a - b) as i16;

                let a = ((d >> (8 * j + 4)) & 0x3) as i8;
                let b = ((d >> (8 * j + 6)) & 0x3) as i8;
                rj.0[1] = (a - b) as i16;
            }
        }
    }

    #[inline]
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
            .as_array_chunks_mut::<2>()
            .zip(buf.as_array_chunks::<3>())
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

    pub fn getnoise_eta1<const K: usize>(
        &mut self,
        prf: &mut Prf,
        seed: &[u8; NOISE_SEED_BYTES],
        nonce: u8,
    ) {
        if K == 2 {
            const ETA1: usize = 3;
            let mut buf = [0u8; ETA1 * KYBER_N / 4];
            prf.absorb_prf(seed, nonce);
            prf.squeeze(&mut buf);
            self.cbd3(&buf);
        } else {
            self.getnoise_eta2(prf, seed, nonce);
        }
    }

    pub fn getnoise_eta2(&mut self, prf: &mut Prf, seed: &[u8; NOISE_SEED_BYTES], nonce: u8) {
        const ETA2: usize = 2;
        prf.absorb_prf(seed, nonce);
        let mut buf = [0u8; ETA2 * KYBER_N / 4];
        prf.absorb_prf(seed, nonce);
        prf.squeeze(&mut buf);
        self.cbd2(&buf);
    }

    #[inline(always)]
    pub fn ntt_and_reduce(&mut self) {
        self.ntt();
        self.reduce();
    }

    pub fn into_array(&self) -> [<KyberFq as Field>::E; Self::NUM_SCALARS] {
        *self.0.map(|f| f.0).flatten_array()
    }

    fn as_scalar_array_mut(
        &mut self,
    ) -> &mut [<<Self as Polynomial>::F as Field>::E; Self::NUM_SCALARS] {
        // FIXME Safety rationale!
        debug_assert_eq!(
            size_of::<[<<Self as Polynomial>::F as Field>::E; Self::NUM_SCALARS]>(),
            size_of::<Self>()
        );

        #[allow(unsafe_code)]
        unsafe {
            transmute(self.as_mut())
        }
    }

    fn as_scalar_array(&self) -> &[<<Self as Polynomial>::F as Field>::E; Self::NUM_SCALARS] {
        // FIXME Safety rationale!
        debug_assert_eq!(
            size_of::<[<<Self as Polynomial>::F as Field>::E; Self::NUM_SCALARS]>(),
            size_of::<Self>()
        );
        #[allow(unsafe_code)]
        unsafe {
            transmute(self.as_ref())
        }
    }

    #[inline]
    pub fn compress_slice<const D: usize>(&self, ct: &mut [u8]) {
        assert_eq!(ct.len(), poly_compressed_bytes(D as u8));

        #[inline(always)]
        fn shift_signed(x: u16, shl: i8) -> u8 {
            if shl >= 0 {
                debug_assert!(shl < 8);
                (x << shl) as u8
            } else {
                let shr = (-shl) as u8;
                (x >> shr) as u8
            }
        }

        for (coeffs, bytes) in self
            .as_scalar_array()
            .as_array_chunks::<{ 4 * 2 }>()
            .zip(ct.as_array_chunks_mut::<D>())
        {
            let mut shl: i8 = 0;
            let mut idx = 0;
            // let mut x = comp_coeffs.next().unwrap(); // array faster?
            for b in bytes {
                debug_assert!(shl < 8);

                *b = shift_signed(compress_d::<D>(coeffs[idx]), shl);

                while D as i8 + shl < 8 {
                    shl += D as i8;
                    idx += 1;
                    *b |= shift_signed(compress_d::<D>(coeffs[idx]), shl);
                }
                shl -= 8;
            }
        }
    }

    #[inline]
    pub fn decompress_slice<const D: usize>(&mut self, ct: &[u8]) {
        assert_eq!(ct.len(), poly_compressed_bytes(D as u8));

        #[inline(always)]
        fn shift_signed<const D: usize>(x: u8, shl: i8) -> u16 {
            if shl >= 0 {
                (x as u16) << shl
            } else {
                (x as u16) >> (-shl)
            }
        }

        for (coeffs, bytes) in self
            .as_scalar_array_mut()
            .as_array_chunks_mut::<{ 4 * 2 }>()
            .zip(ct.as_array_chunks::<D>())
        {
            let mut shl: i8 = 0;
            let mut idx = 0;

            for c in coeffs {
                let mut d_bits = shift_signed::<D>(bytes[idx], shl);

                while shl + 8 < D as i8 {
                    shl += 8;
                    idx += 1;
                    d_bits |= shift_signed::<D>(bytes[idx], shl);
                }
                shl -= D as i8;
                *c = decompress_d::<D>(d_bits);
            }
        }
    }

    #[inline]
    pub fn compress<const D: usize>(&self, ct: &mut [[u8; D]; 32]) {
        // assert_eq!(ct.len(), poly_compressed_bytes(D as u8));
        // n: number of bytes, m: number of poly elements (2 * i16)
        // g = gcd(d,4)
        // 4*n = d*m
        // let m: usize = 4 / gcd_u8(D as u8, 4) as usize;
        // let n: usize = (D as u8 / gcd_u8(D as u8, 4)) as usize;

        #[inline(always)]
        fn shift_signed(x: u16, shl: i8) -> u8 {
            if shl >= 0 {
                debug_assert!(shl < 8);
                (x << shl) as u8
            } else {
                let shr = (-shl) as u8;
                (x >> shr) as u8
            }
        }

        for (coeffs, bytes) in self
            .as_scalar_array()
            .as_array_chunks::<{ 4 * 2 }>()
            .zip(ct)
        {
            // let mut comp_coeffs = coeff_pairs
            // .iter()
            // .flat_map(|f| f.0.map(|x| compress_d::<D>(x)));
            // only d bits of t[i] are valid, others set to 0
            // let mut valid_bits = d as i8;
            // let mut byte_idx = 0;
            // let mut shl: i8 = 0;
            // for x in comp_coeffs {
            //     while valid_bits > 0 {
            //         bytes[byte_idx] |= shift_signed(x, shl);
            //         valid_bits += shl - 8;

            //         byte_idx += 1;
            //     }
            //     valid_bits = d as i8;
            //     shl = 0;
            // }
            let mut shl: i8 = 0;
            let mut idx = 0;
            
            for b in bytes {
                debug_assert!(shl < 8);

                *b = shift_signed(compress_d::<D>(coeffs[idx]), shl);

                while D as i8 + shl < 8 {
                    shl += D as i8;
                    idx += 1;
                    *b |= shift_signed(compress_d::<D>(coeffs[idx]), shl);
                }
                shl -= 8;
            }
        }
    }

    #[inline]
    pub fn decompress<const D: usize>(&mut self, ct: &[[u8; D]; 32]) {
        #[inline(always)]
        fn shift_signed<const D: usize>(x: u8, shl: i8) -> u16 {
            if shl >= 0 {
                (x as u16) << shl
            } else {
                (x as u16) >> (-shl)
            }
        }

        for (coeff_pairs, bytes) in self.as_mut().chunks_exact_mut(4).zip(ct) {
            let mut shl: i8 = 0;
            let mut idx = 0;

            for c in coeff_pairs.iter_mut().flat_map(|f| f.0.iter_mut()) {
                let mut d_bits = shift_signed::<D>(bytes[idx], shl);

                while shl + 8 < D as i8 {
                    shl += 8;
                    idx += 1;
                    d_bits |= shift_signed::<D>(bytes[idx], shl);
                }
                shl -= D as i8;
                *c = decompress_d::<D>(d_bits);
            }
        }
    }

    pub fn set_from_message(&mut self, msg: &[u8; KYBER_N / 8]) {
        const ONE_COEFF: i16 = (KYBER_Q + 1) / 2;
        for (i, byte) in msg.iter().enumerate() {
            for j in 0..4 {
                let mask0 = 0i16.wrapping_sub(((*byte) >> (2 * j) & 1) as i16);
                let mask1 = 0i16.wrapping_sub(((*byte) >> (2 * j + 1) & 1) as i16);

                debug_assert!(mask0 == 0 || mask0 == -1);
                debug_assert!(mask1 == 0 || mask1 == -1);

                self[4 * i + j].0 = [mask0 & ONE_COEFF, mask1 & ONE_COEFF];

                let x = self[4 * i + j].0;
                debug_assert!(x[0] == 0 || x[0] == ONE_COEFF);
                debug_assert!(x[1] == 0 || x[1] == ONE_COEFF);
            }
        }
    }

    #[inline(always)]
    pub fn from_message(msg: &[u8; KYBER_N / 8]) -> Self {
        let mut poly = Self::default();
        poly.set_from_message(msg);
        poly
    }

    pub fn into_message(&self, msg: &mut [u8; 32]) {
        for (coeff_pairs, byte) in self.as_ref().chunks_exact(4).zip(msg.iter_mut()) {
            *byte = 0;
            for (j, c) in coeff_pairs
                .iter()
                .flat_map(|f| f.reduce().0.map(|u| compress_d::<1>(u) as u8))
                .enumerate()
            {
                *byte |= c << j;
            }
        }
    }

    /// Inplace conversion of all coefficients of a polynomial from normal domain to Montgomery domain
    /// # Arguments
    /// * `r` - Input/output polynomial
    #[inline]
    pub fn into_montgomery(&mut self) {
        for coeff in self {
            coeff.to_mont();
        }
    }
}

use rand::{CryptoRng, Rng, RngCore};

impl KyberPoly {
    #[doc(hidden)]
    pub fn new_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut poly = Self::default();
        fn frand<R: RngCore + CryptoRng>(rng: &mut R) -> i16 {
            rng.gen_range(-KYBER_Q / 2..=KYBER_Q / 2)
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
    use crate::field::kyber::{KYBER_Q, QINV};
    use crate::polyvec::KyberPolyVec;
    use crate::utils::*;
    extern crate std;
    use super::*;
    use crate::poly::SizedPolynomial;
    use crate::utils::unsafe_utils::flatten::{
        FlattenArray, FlattenSlice, FlattenSliceMut, FlattenTwice, FlattenTwiceMut,
    };
    use crystals_cref::kyber as cref;
    use std::*;

    const M: usize = KyberPoly::NUM_SCALARS / 8;

    #[test]
    fn q_inv_test() {
        assert_eq!(QINV, invm(KYBER_Q as i32, 1 << 16).unwrap() as i16);
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

    #[test]
    #[cfg(not(miri))]
    fn test_ntt_vs_ref() {
        let mut rng = rand::thread_rng();
        for _ in 0..3_000 {
            let mut poly = KyberPoly::new_random(&mut rng);
            let mut p = poly.into_array();

            crystals_cref::kyber::ntt(&mut p);

            poly.ntt();
            poly.reduce();

            assert_eq!(poly.into_array(), p);
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn test_invntt_vs_ref() {
        let mut rng = rand::thread_rng();
        for _ in 0..3_000 {
            let mut poly = KyberPoly::new_random(&mut rng);
            let mut p = poly.into_array();
            poly.inv_ntt();
            poly.reduce();
            crystals_cref::kyber::inv_ntt(&mut p);
            crystals_cref::kyber::poly_reduce(&mut p);

            assert_eq!(poly.into_array(), p);
        }
    }

    #[test]
    #[cfg(not(miri))]
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

            assert_eq!(poly_r.into_array(), r);
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn test_cbd2_vs_ref() {
        let mut rng = rand::thread_rng();
        for _ in 0..1_000 {
            let mut poly = KyberPoly::new_random(&mut rng);
            let mut p = poly.into_array();

            let mut buf = [0u8; 2 * KYBER_N / 4];
            rng.fill(buf.as_mut());

            poly.cbd2(&buf);
            crystals_cref::kyber::poly_cbd_eta_eq_2(&mut p, &buf);

            assert_eq!(poly.into_array(), p);
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn test_cbd3_vs_ref() {
        let mut rng = rand::thread_rng();
        for _ in 0..1_000 {
            let mut poly = KyberPoly::new_random(&mut rng);
            let mut p = poly.into_array();

            let mut buf = [0u8; 3 * KYBER_N / 4];
            rng.fill(buf.as_mut());

            poly.cbd3(&buf);
            crystals_cref::kyber::poly_cbd_eta_eq_3(&mut p, &buf);

            assert_eq!(poly.into_array(), p);
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn test_getnoise_eta3_vs_ref() {
        let mut rng = rand::thread_rng();
        let mut prf = Prf::default();
        for _ in 0..1_000 {
            let mut poly = KyberPoly::new_random(&mut rng);
            let mut p = poly.into_array();

            let mut seed = [0u8; NOISE_SEED_BYTES];
            rng.fill(seed.as_mut());
            let nonce = rand::random();

            poly.getnoise_eta1::<2>(&mut prf, &seed, nonce);
            crystals_cref::kyber::poly_getnoise_eta_eq_3(&mut p, &seed, nonce);

            assert_eq!(poly.into_array(), p);
        }
    }

    #[test]
    #[cfg(not(miri))] // miri does not support calling foreign functions
    fn test_polycompress_vs_ref() {
        for _ in 0..1_000 {
            let poly = KyberPoly::new_random(&mut rand::thread_rng());

            {
                const D: u8 = 4;
                let mut ct = [[0u8; { D as usize }]; M];
                let mut ct_ref = [0u8; poly_compressed_bytes(D)];

                poly.compress::<{ D as usize }>(&mut ct);
                cref::poly_compress::<2>(&mut ct_ref, &poly.as_scalar_array());
                assert_eq!(ct.flatten_array(), &ct_ref);
            }

            {
                const D: u8 = 4;
                let mut ct = [[0u8; { D as usize }]; M];
                let mut ct_ref = [0u8; poly_compressed_bytes(D)];

                poly.compress::<{ D as usize }>(&mut ct);
                cref::poly_compress::<3>(&mut ct_ref, &poly.as_scalar_array());
                assert_eq!(ct.flatten_array(), &ct_ref);
            }
            {
                const D: u8 = 5;
                let mut ct = [[0u8; { D as usize }]; M];
                let mut ct_ref = [0u8; poly_compressed_bytes(D)];

                poly.compress::<{ D as usize }>(&mut ct);
                cref::poly_compress::<4>(&mut ct_ref, &poly.as_scalar_array());
                assert_eq!(ct.flatten_array(), &ct_ref);
            }
        }
    }

    fn test_poly_decompress_vs_ref<const K: usize, const D: usize>() {
        {
            let mut rng = rand::thread_rng();
            let mut poly_ref = [0i16; KYBER_N];
            let mut poly = KyberPoly::default();
            let mut ct = [[0u8; D]; M];

            for _ in 0..5_000 {
                rng.fill_bytes(ct.flatten_slice_mut());

                poly.decompress::<D>(&mut ct);
                cref::poly_decompress::<K>(&mut poly_ref, ct.flatten_slice());
                assert_eq!(poly.as_scalar_array(), &poly_ref);
            }
        }
    }

    fn test_polyvec_decompress_vs_ref<const K: usize, const D: usize>() {
        {
            let mut rng = rand::thread_rng();
            let mut pv_ref = [[0i16; KYBER_N]; K];
            let mut pv = KyberPolyVec::<K>::default();
            let mut ct = [[[0u8; D]; M]; K];

            for _ in 0..1_000 {
                rng.fill_bytes(ct.flatten_twice_mut());

                pv.decompress::<D>(&mut ct);
                cref::polyvec_decompress::<K>(&mut pv_ref, ct.flatten_twice());
                for (p, p_ref) in pv.into_iter().zip(pv_ref) {
                    assert_eq!(p.as_scalar_array(), &p_ref);
                }
            }
        }
    }

    #[test]
    #[cfg(not(miri))] // miri does not support calling foreign functions
    fn polyvec_decompress_vs_ref_2() {
        test_polyvec_decompress_vs_ref::<2, 10>();
    }

    #[test]
    #[cfg(not(miri))]
    fn polyvec_decompress_vs_ref_3() {
        test_polyvec_decompress_vs_ref::<3, 10>();
    }

    #[test]
    #[cfg(not(miri))]
    fn polyvec_decompress_vs_ref_4() {
        test_polyvec_decompress_vs_ref::<4, 11>();
    }

    #[test]
    #[cfg(not(miri))] // miri does not support calling foreign functions
    fn poly_decompress_vs_ref_2() {
        test_poly_decompress_vs_ref::<2, 4>();
    }
    #[test]
    #[cfg(not(miri))]
    fn poly_decompress_vs_ref_3() {
        test_poly_decompress_vs_ref::<3, 4>();
    }
    #[test]
    #[cfg(not(miri))]
    fn poly_decompress_vs_ref_4() {
        test_poly_decompress_vs_ref::<4, 5>();
    }
}
