use crate::lib::marker::PhantomData;
use crate::poly::kyber::poly_compressed_bytes_for_k;
use crate::utils::flatten::{FlattenSlice, FlattenSliceMut, FlattenTwice, FlattenTwiceMut};
use crate::utils::gcd_u8;
use crate::{
    poly::{
        kyber::{
            compress_d, poly_compressed_bytes, polyvec_compressed_bytes_for_k, KyberPoly, KYBER_N,
        },
        PolynomialTrait,
    },
    polyvec::{KyberPolyVec, PolynomialVector},
    utils::{flatten::FlattenArray, split::Splitter},
};

#[rustfmt::skip] // rustfmt BUG
#[derive(Debug)]
pub struct Ciphertext<
    const D_POLY: usize,
    const D_PV: usize,
    const K: usize = D_POLY,//
    const M: usize = { KYBER_N / 8 }, //
    P: PolynomialTrait = KyberPoly, //
> //
{
    v: [[u8; D_POLY]; M],
    b: [[[u8; D_PV]; M]; K],
    _phantom: PhantomData<*const P>,
}

impl<const D_POLY: usize, const D_PV: usize, const M: usize, const K: usize> Default
    for Ciphertext<D_POLY, D_PV, K, M>
{
    fn default() -> Self {
        Ciphertext {
            v: [[0u8; D_POLY]; M],
            b: [[[0u8; D_PV]; M]; K],
            _phantom: PhantomData::default(),
        }
    }
}

pub trait CompressedCiphertex {
    const M: usize = KYBER_N / 8;

    fn poly_bytes(&self) -> &[u8];
    fn polyvec_bytes(&self) -> &[u8];
    fn poly_bytes_mut(&mut self) -> &mut [u8];
    fn polyvec_bytes_mut(&mut self) -> &mut [u8];
}

pub trait CompressCiphertext<const K: usize> {
    const K: usize = K;
    type PolyType: PolynomialTrait;
    type PolyVecType: PolynomialVector;

    fn compress_poly(&mut self, v: &Self::PolyType);
    fn decompress_poly(&self, v: &mut Self::PolyType);

    fn compress_polyvec(&mut self, b: &Self::PolyVecType);
    fn decompress_polyvec(&self, b: &mut Self::PolyVecType);
}

const K23_POLY_COMPRESSED_BYTES: usize = poly_compressed_bytes(4);
const K4_POLY_COMPRESSED_BYTES: usize = poly_compressed_bytes(5);
const K2_POLYVEC_COMPRESSED_BYTES: usize = polyvec_compressed_bytes_for_k::<2>();
const K3_POLYVEC_COMPRESSED_BYTES: usize = polyvec_compressed_bytes_for_k::<3>();
const K4_POLYVEC_COMPRESSED_BYTES: usize = polyvec_compressed_bytes_for_k::<4>();

pub const K2_CT_BYTES: usize = K23_POLY_COMPRESSED_BYTES + K2_POLYVEC_COMPRESSED_BYTES;
pub const K3_CT_BYTES: usize = K23_POLY_COMPRESSED_BYTES + K3_POLYVEC_COMPRESSED_BYTES;
pub const K4_CT_BYTES: usize = K4_POLY_COMPRESSED_BYTES + K4_POLYVEC_COMPRESSED_BYTES;

// 4:1 compression
#[inline]
fn polycompress_d4(ct: &mut [u8; poly_compressed_bytes(4)], poly: &KyberPoly) {
    const D: u8 = 4;
    // n: number of bytes, m: number of poly elements (2 * i16)
    // 4*n = d*m
    // const M: usize = 4 / gcd_4(D) as usize;
    // const N: usize = (D / gcd_4(D)) as usize;
    // debug_assert!(M == 1 && N == 1);

    for (f, r) in poly.into_iter().zip(ct.iter_mut()) {
        let t = f.0.map(|x| compress_d::<{ D as usize }>(x) as u8);
        *r = t[0] | (t[1] << D);
    }
}

// 16:5 compression
#[inline]
fn polycompress_d5(ct: &mut [u8; poly_compressed_bytes(5)], poly: &KyberPoly) {
    const D: u8 = 5;
    // n: number of bytes, m: number of poly elements (2 * i16)
    // 4*n = d*m
    const M: usize = 4 / gcd_u8(D, 4) as usize;
    const N: usize = (D / gcd_u8(D, 4)) as usize;
    // for (f4, r) in poly.as_ref().chunks_exact(4).zip(ct.chunks_exact_mut(5)) {
    //     debug_assert_eq!(f4.len(), 4); // 8 i16 scalars
    //     debug_assert_eq!(r.len(), 5);

    //     let mut t = [0u8; 8];
    //     for (ti, xi) in t.iter_mut().zip(
    //         f4.into_iter()
    //             .map(|f| f.0.map(|x| compress_4_5(x, D)))
    //             .flatten(),
    //     ) {
    //         *ti = xi;
    //     }
    for (f4, r) in poly
        .as_ref()
        .as_array_chunks::<M>()
        .zip(ct.as_array_chunks_mut::<N>())
    {
        let a = f4.map(|f| f.0.map(|x| compress_d::<{ D as usize }>(x) as u8));
        let t: &[u8; 8] = a.flatten_array();

        r[0] = t[0] | (t[1] << 5);
        r[1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
        r[2] = (t[3] >> 1) | (t[4] << 4);
        r[3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
        r[4] = (t[6] >> 2) | (t[7] << 3);
    }
}

// 8:5 compression
#[inline]
fn polycompress_d10(ct: &mut [u8; poly_compressed_bytes(10)], poly: &KyberPoly) {
    const D: u8 = 10;
    // n: number of bytes, m: number of poly elements (2 * i16)
    // 4*n = d*m
    const M: usize = 4 / gcd_u8(D, 4) as usize;
    const N: usize = (D / gcd_u8(D, 4)) as usize;
    for (f2, r) in poly
        .as_ref()
        .as_array_chunks::<M>()
        .zip(ct.as_array_chunks_mut::<N>())
    {
        let a = f2.map(|f| f.0.map(|x| compress_d::<{ D as usize }>(x)));
        let t: &[u16; 4] = a.flatten_array();

        r[0] = t[0] as u8;
        r[1] = (t[0] >> 8) as u8 | (t[1] << 2) as u8;
        r[2] = (t[1] >> 6) as u8 | (t[2] << 4) as u8;
        r[3] = (t[2] >> 4) as u8 | (t[3] << 6) as u8;
        r[4] = (t[3] >> 2) as u8;
    }
}

// 16:11 compression
#[inline]
fn polycompress_d11(ct: &mut [u8; poly_compressed_bytes(11)], poly: &KyberPoly) {
    const D: u8 = 11;
    // n: number of bytes, m: number of poly elements (2 * i16)
    // 4*n = d*m
    const M: usize = 4 / gcd_u8(D, 4) as usize;
    const N: usize = (D / gcd_u8(D, 4)) as usize;
    for (f4, r) in poly
        .as_ref()
        .as_array_chunks::<4>()
        .zip(ct.as_array_chunks_mut::<11>())
    {
        let a = f4.map(|f| f.0.map(|x| compress_d::<{ D as usize }>(x)));
        let t: &[u16; 8] = a.flatten_array();

        r[0] = t[0] as u8;
        r[1] = (t[0] >> 8) as u8 | (t[1] << 3) as u8;
        r[2] = (t[1] >> 5) as u8 | (t[2] << 6) as u8;
        r[3] = (t[2] >> 2) as u8;
        r[4] = (t[2] >> 10) as u8 | (t[3] << 1) as u8;
        r[5] = (t[3] >> 7) as u8 | (t[4] << 4) as u8;
        r[6] = (t[4] >> 4) as u8 | (t[5] << 7) as u8;
        r[7] = (t[5] >> 1) as u8;
        r[8] = (t[5] >> 9) as u8 | (t[6] << 2) as u8;
        r[9] = (t[6] >> 6) as u8 | (t[7] << 5) as u8;
        r[10] = (t[7] >> 3) as u8;
    }
}

impl<
        P: PolynomialTrait,
        const D_POLY: usize,
        const D_PV: usize,
        const M: usize,
        const K: usize,
    > CompressedCiphertex for Ciphertext<D_POLY, D_PV, K, M, P>
{
    const M: usize = M;

    fn poly_bytes(&self) -> &[u8] {
        self.v.flatten_slice()
    }
    fn polyvec_bytes(&self) -> &[u8] {
        self.b.flatten_twice()
    }

    fn poly_bytes_mut(&mut self) -> &mut [u8] {
        self.v.flatten_slice_mut()
    }

    fn polyvec_bytes_mut(&mut self) -> &mut [u8] {
        self.b.flatten_twice_mut()
    }
}

impl CompressCiphertext<2> for Ciphertext<4, 10, 2, 32, KyberPoly> {
    const K: usize = 2;

    type PolyType = KyberPoly;

    type PolyVecType = KyberPolyVec<2>;

    fn compress_poly(&mut self, v: &Self::PolyType) {
        v.compress(&mut self.v)
    }

    fn decompress_poly(&self, v: &mut Self::PolyType) {
        v.decompress(&self.v)
    }

    fn compress_polyvec(&mut self, b: &Self::PolyVecType) {
        b.compress(&mut self.b)
    }

    fn decompress_polyvec(&self, b: &mut Self::PolyVecType) {
        b.decompress(&self.b)
    }
}

impl CompressCiphertext<3> for Ciphertext<4, 10, 3, 32, KyberPoly> {
    const K: usize = 3;

    type PolyType = KyberPoly;

    type PolyVecType = KyberPolyVec<3>;

    fn compress_poly(&mut self, v: &Self::PolyType) {
        v.compress(&mut self.v)
    }

    fn decompress_poly(&self, v: &mut Self::PolyType) {
        v.decompress(&self.v)
    }

    fn compress_polyvec(&mut self, b: &Self::PolyVecType) {
        b.compress(&mut self.b)
    }

    fn decompress_polyvec(&self, b: &mut Self::PolyVecType) {
        b.decompress(&self.b)
    }
}

impl CompressCiphertext<4> for Ciphertext<5, 11, 4, 32, KyberPoly> {
    const K: usize = 4;

    type PolyType = KyberPoly;

    type PolyVecType = KyberPolyVec<4>;

    fn compress_poly(&mut self, v: &Self::PolyType) {
        v.compress(&mut self.v)
    }

    fn decompress_poly(&self, v: &mut Self::PolyType) {
        v.decompress(&self.v)
    }

    fn compress_polyvec(&mut self, b: &Self::PolyVecType) {
        b.compress(&mut self.b)
    }

    fn decompress_polyvec(&self, b: &mut Self::PolyVecType) {
        b.decompress(&self.b)
    }
}

#[cfg(any(feature = "std", feature = "alloc", test))]
pub struct VecCipherText<const K: usize>(crate::lib::Vec<u8>);

#[cfg(any(feature = "std", feature = "alloc", test))]
impl<const K: usize> Default for VecCipherText<K> {
    fn default() -> Self {
        VecCipherText(crate::lib::from_elem(
            0,
            polyvec_compressed_bytes_for_k::<K>() + poly_compressed_bytes_for_k::<K>(),
        ))
    }
}

#[cfg(any(feature = "std", feature = "alloc", test))]
impl<const K: usize> AsRef<[u8]> for VecCipherText<K> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(any(feature = "std", feature = "alloc", test))]
impl<const K: usize> AsMut<[u8]> for VecCipherText<K> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

#[cfg(any(feature = "std", feature = "alloc", test))]
impl<const K: usize> CompressedCiphertex for VecCipherText<K> {
    const M: usize = KYBER_N / 8;

    fn poly_bytes(&self) -> &[u8] {
        &self.0[polyvec_compressed_bytes_for_k::<K>()..]
    }

    fn polyvec_bytes(&self) -> &[u8] {
        &self.0[..polyvec_compressed_bytes_for_k::<K>()]
    }

    fn poly_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0[polyvec_compressed_bytes_for_k::<K>()..]
    }

    fn polyvec_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0[..polyvec_compressed_bytes_for_k::<K>()]
    }
}

#[cfg(any(feature = "std", feature = "alloc", test))]
impl<const K: usize> CompressCiphertext<K> for VecCipherText<K> {
    fn compress_poly(&mut self, v: &KyberPoly) {
        let ct = &mut self.0[polyvec_compressed_bytes_for_k::<K>()..];
        assert_eq!(ct.len(), poly_compressed_bytes_for_k::<K>());
        match K {
            2 | 3 => {
                v.compress_slice::<4>(ct);
            }
            4 => {
                v.compress_slice::<5>(ct);
            }
            _ => unreachable!(),
        }
    }

    fn compress_polyvec(&mut self, b: &KyberPolyVec<K>) {
        let pvct = &mut self.0[..polyvec_compressed_bytes_for_k::<K>()];
        assert_eq!(pvct.len(), polyvec_compressed_bytes_for_k::<K>());
        for (poly, bytes) in b
            .into_iter()
            .zip(pvct.chunks_exact_mut(poly_compressed_bytes_for_k::<K>()))
        {
            match K {
                2 | 3 => {
                    poly.compress_slice::<10>(bytes);
                }
                4 => {
                    poly.compress_slice::<11>(bytes);
                }
                _ => unreachable!(),
            }
        }
    }

    const K: usize = K;

    type PolyType = KyberPoly;

    type PolyVecType = KyberPolyVec<K>;

    fn decompress_poly(&self, v: &mut Self::PolyType) {
        let ct = &self.0[polyvec_compressed_bytes_for_k::<K>()..];
        assert_eq!(ct.len(), poly_compressed_bytes_for_k::<K>());
        match K {
            2 | 3 => {
                v.decompress_slice::<4>(ct);
            }
            4 => {
                v.decompress_slice::<5>(ct);
            }
            _ => unreachable!(),
        }
    }

    fn decompress_polyvec(&self, b: &mut Self::PolyVecType) {
        let pvct = &self.0[..polyvec_compressed_bytes_for_k::<K>()];
        assert_eq!(pvct.len(), polyvec_compressed_bytes_for_k::<K>());
        let ct_per_poly_len = pvct.len() / K;
        for (poly, bytes) in b.into_iter().zip(pvct.chunks_exact(ct_per_poly_len)) {
            match K {
                2 | 3 => {
                    poly.decompress_slice::<10>(bytes);
                }
                4 => {
                    poly.decompress_slice::<11>(bytes);
                }
                _ => unreachable!(),
            }
        }
    }
}

// impl CompressCiphertext<3> for Ciphertext<3, K3_CT_BYTES> {
//     fn compress_poly(&mut self, v: &KyberPoly) {
//         let (_, ct_poly): (
//             &mut [u8; K3_POLYVEC_COMPRESSED_BYTES],
//             &mut [u8; K23_POLY_COMPRESSED_BYTES],
//         ) = self.0.dissect_mut();
//         polycompress_d4(ct_poly, v);
//     }

//     fn compress_polyvec(&mut self, b: &KyberPolyVec<3>) {
//         let (ct_polyvec, _): (
//             &mut [u8; K3_POLYVEC_COMPRESSED_BYTES],
//             &mut [u8; K23_POLY_COMPRESSED_BYTES],
//         ) = self.0.dissect_mut();
//         for (poly, ct_chunk) in b.into_iter().zip(ct_polyvec.as_array_chunks_mut()) {
//             polycompress_d10(ct_chunk, poly);
//         }
//     }
// }

// impl CompressCiphertext<4> for Ciphertext<4, K4_CT_BYTES> {
//     fn compress_poly(&mut self, v: &KyberPoly) {
//         let (_, ct_poly): (
//             &mut [u8; K4_POLYVEC_COMPRESSED_BYTES],
//             &mut [u8; K4_POLY_COMPRESSED_BYTES],
//         ) = self.0.dissect_mut();
//         polycompress_d5(ct_poly, v);
//     }

//     fn compress_polyvec(&mut self, b: &KyberPolyVec<4>) {
//         let (ct_polyvec, _): (
//             &mut [u8; K4_POLYVEC_COMPRESSED_BYTES],
//             &mut [u8; K4_POLY_COMPRESSED_BYTES],
//         ) = self.0.dissect_mut();
//         for (poly, ct_chunk) in b.into_iter().zip(ct_polyvec.as_array_chunks_mut()) {
//             polycompress_d10(ct_chunk, poly);
//         }
//     }
// }

// impl<const K: usize> CompressCiphertext<K> for &mut [u8] {
//     fn compress_poly(&mut self, v: &KyberPoly) {
//         assert_eq!(self.len(), KYBER_N * (K / 4 + 4) / 8);
//         let (_, ct_poly): (
//             &mut [u8; K3_POLYVEC_COMPRESSED_BYTES],
//             &mut [u8; K23_POLY_COMPRESSED_BYTES],
//         ) = self.0.dissect_mut();
//         polycompress_d4(ct_poly, v);
//     }

//     fn compress_polyvec(&mut self, b: &KyberPolyVec<K>) {
//         assert_eq!(self.len(), KYBER_N * (K / 4 + 10) / 8);
//         let (ct_polyvec, _): (
//             &mut [u8; K3_POLYVEC_COMPRESSED_BYTES],
//             &mut [u8; K23_POLY_COMPRESSED_BYTES],
//         ) = self.0.dissect_mut();
//         for (poly, ct_chunk) in b.into_iter().zip(ct_polyvec.into_array_chunks_mut()) {
//             polycompress_d10(ct_chunk, poly);
//         }
//     }
// }

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::poly::Polynomial;
    use crystals_cref::kyber as cref;
    use std::*;

    const M: usize = KyberPoly::NUM_SCALARS / 8;

    #[test]
    #[cfg(not(miri))] // miri does not support calling foreign functions
    fn test_polycompress_d_vs_ref_pv() {
        for _ in 0..1_000 {
            {
                const K: usize = 2;
                const D: u8 = 10;

                let pv = KyberPolyVec::<K>::new_random(&mut rand::thread_rng());
                let mut ct = [[[0u8; { D as usize }]; M]; K];
                let mut ct_ref = [0u8; poly_compressed_bytes(D) * K];

                pv.compress::<{ D as usize }>(&mut ct);
                cref::polyvec_compress::<K>(
                    &mut ct_ref,
                    &pv.as_ref().map(|p| *p.as_scalar_array()),
                );
                assert_eq!(
                    FlattenArray::<_, { D as usize }, {M  * K}, { M  * K* D as usize }>::flatten_array(
                        ct.flatten_array()
                    ),
                    &ct_ref
                );
            }

            {
                const K: usize = 3;
                const D: u8 = 10;

                let pv = KyberPolyVec::<K>::new_random(&mut rand::thread_rng());
                let mut ct = [[[0u8; { D as usize }]; M]; K];
                let mut ct_ref = [0u8; polyvec_compressed_bytes_for_k::<K>()];

                pv.compress::<{ D as usize }>(&mut ct);
                cref::polyvec_compress::<K>(
                    &mut ct_ref,
                    &pv.as_ref().map(|p| *p.as_scalar_array()),
                );
                let t: &[[_; D as usize]; K * M] = ct.flatten_array();
                assert_eq!(t.flatten_array(), &ct_ref, "\nct_ref: {:?}\n", ct_ref,);
            }
            {
                const K: usize = 4;
                const D: u8 = 11;

                let pv = KyberPolyVec::<K>::new_random(&mut rand::thread_rng());
                let mut ct = [[[0u8; { D as usize }]; M]; K];
                let mut ct_ref = [0u8; polyvec_compressed_bytes_for_k::<K>()];

                pv.compress::<{ D as usize }>(&mut ct);
                cref::polyvec_compress::<K>(
                    &mut ct_ref,
                    &pv.as_ref().map(|p| *p.as_scalar_array()),
                );
                let t: &[[_; D as usize]; K * M] = ct.flatten_array();
                assert_eq!(t.flatten_array(), &ct_ref, "\nct_ref: {:?}\n", ct_ref,);
            }
        }
    }
}
