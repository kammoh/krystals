mod bindings_512 {
    #![allow(unsafe_code)]
    #![allow(warnings)]
    extern crate cty;
    include!(concat!(env!("OUT_DIR"), "/kyber512_bindings.rs"));
}

mod bindings_768 {
    #![allow(unsafe_code)]
    #![allow(warnings)]
    extern crate cty;
    include!(concat!(env!("OUT_DIR"), "/kyber768_bindings.rs"));
}

mod bindings_1024 {
    #![allow(unsafe_code)]
    #![allow(warnings)]
    extern crate cty;
    include!(concat!(env!("OUT_DIR"), "/kyber1024_bindings.rs"));
}

const KYBER_N: usize = bindings_512::KYBER_N as usize;
const SEEDBYTES: usize = bindings_512::KYBER_SYMBYTES as usize;
const KYBER_POLYBYTES: usize = bindings_512::KYBER_POLYBYTES as usize;

pub type CPoly = [i16; KYBER_N];
pub type CPolyVec<const K: usize> = [[i16; KYBER_N]; K];

pub fn ntt(poly: &mut CPoly) {
    #[allow(unsafe_code)]
    unsafe {
        bindings_512::pqcrystals_kyber512_ref_poly_ntt(poly.as_mut_ptr() as *mut _);
    }
}

pub fn polyvec_ntt<const K: usize>(pv: &mut CPolyVec<K>) {
    #![allow(unsafe_code)]
    match K {
        2 => unsafe {
            bindings_512::pqcrystals_kyber512_ref_polyvec_ntt(pv.as_mut_ptr() as *mut _);
        },
        3 => unsafe {
            bindings_768::pqcrystals_kyber768_ref_polyvec_ntt(pv.as_mut_ptr() as *mut _);
        },
        4 => unsafe {
            bindings_1024::pqcrystals_kyber1024_ref_polyvec_ntt(pv.as_mut_ptr() as *mut _);
        },
        _ => unreachable!(),
    }
}

pub fn polyvec_invntt_tomont<const K: usize>(pv: &mut CPolyVec<K>) {
    #![allow(unsafe_code)]
    match K {
        2 => unsafe {
            bindings_512::pqcrystals_kyber512_ref_polyvec_invntt_tomont(pv.as_mut_ptr() as *mut _);
        },
        3 => unsafe {
            bindings_768::pqcrystals_kyber768_ref_polyvec_invntt_tomont(pv.as_mut_ptr() as *mut _);
        },
        4 => unsafe {
            bindings_1024::pqcrystals_kyber1024_ref_polyvec_invntt_tomont(pv.as_mut_ptr() as *mut _);
        },
        _ => unreachable!(),
    }
}

pub fn gen_matrix<const K: usize>(
    a: &mut [[CPoly; K]; K],
    seed: &[u8; SEEDBYTES],
    transposed: bool,
) {
    #![allow(unsafe_code)]
    let transposed = if transposed { 1 } else { 0 };

    match K {
        2 => unsafe {
            bindings_512::pqcrystals_kyber512_ref_gen_matrix(
                a.as_mut_ptr() as *mut _,
                seed.as_ptr(),
                transposed,
            );
        },
        3 => unsafe {
            bindings_768::pqcrystals_kyber768_ref_gen_matrix(
                a.as_mut_ptr() as *mut _,
                seed.as_ptr(),
                transposed,
            );
        },
        4 => unsafe {
            bindings_1024::pqcrystals_kyber1024_ref_gen_matrix(
                a.as_mut_ptr() as *mut _,
                seed.as_ptr(),
                transposed,
            );
        },
        _ => unreachable!(),
    }
}

pub fn inv_ntt(poly: &mut CPoly) {
    #[allow(unsafe_code)]
    unsafe {
        bindings_512::pqcrystals_kyber512_ref_poly_invntt_tomont(poly.as_mut_ptr() as *mut _);
    }
}

#[inline]
pub fn poly_reduce(poly: &mut CPoly) {
    #[allow(unsafe_code)]
    unsafe {
        bindings_512::pqcrystals_kyber512_ref_poly_reduce(poly.as_mut_ptr() as *mut _);
    }
}

#[inline]
pub fn basemul(r: &mut [i16; 2], a: &[i16; 2], b: &[i16; 2], zeta: i16) {
    #[allow(unsafe_code)]
    unsafe {
        bindings_512::pqcrystals_kyber512_ref_basemul(r.as_mut_ptr(), a.as_ptr(), b.as_ptr(), zeta);
    }
}

#[inline]
pub fn poly_pointwise_montgomery(r: &mut CPoly, a: &CPoly, b: &CPoly) {
    #[allow(unsafe_code)]
    unsafe {
        bindings_512::pqcrystals_kyber512_ref_poly_basemul_montgomery(
            r.as_mut_ptr() as _,
            a.as_ptr() as _,
            b.as_ptr() as _,
        );
    }
}

#[inline]
pub fn poly_compress<const K: usize>(r: &mut [u8], a: &CPoly) {
    match K {
        2 => {
            // D = 4
            debug_assert_eq!(r.len(), 128);
            #[allow(unsafe_code)]
            unsafe {
                bindings_512::pqcrystals_kyber512_ref_poly_compress(
                    r.as_mut_ptr() as _,
                    a.as_ptr() as _,
                );
            }
        }
        3 => {
            // D = 4
            debug_assert_eq!(r.len(), 128);
            #[allow(unsafe_code)]
            unsafe {
                bindings_768::pqcrystals_kyber768_ref_poly_compress(
                    r.as_mut_ptr() as _,
                    a.as_ptr() as _,
                );
            }
        }
        4 => {
            // D = 5
            debug_assert_eq!(r.len(), 160);
            #[allow(unsafe_code)]
            unsafe {
                bindings_1024::pqcrystals_kyber1024_ref_poly_compress(
                    r.as_mut_ptr() as _,
                    a.as_ptr() as _,
                );
            }
        }
        _ => unreachable!(),
    }
}

#[inline]
pub fn polyvec_compress<const K: usize>(r: &mut [u8], a: &CPolyVec<K>) {
    match K {
        2 => {
            // D = 4
            debug_assert_eq!(r.len(), K * 320);
            #[allow(unsafe_code)]
            unsafe {
                bindings_512::pqcrystals_kyber512_ref_polyvec_compress(
                    r.as_mut_ptr() as _,
                    a.as_ptr() as _,
                );
            }
        }
        3 => {
            // D = 4
            debug_assert_eq!(r.len(), K * 320);
            #[allow(unsafe_code)]
            unsafe {
                bindings_768::pqcrystals_kyber768_ref_polyvec_compress(
                    r.as_mut_ptr() as _,
                    a.as_ptr() as _,
                );
            }
        }
        4 => {
            // D = 5
            debug_assert_eq!(r.len(), K * 352);
            #[allow(unsafe_code)]
            unsafe {
                bindings_1024::pqcrystals_kyber1024_ref_polyvec_compress(
                    r.as_mut_ptr() as _,
                    a.as_ptr() as _,
                );
            }
        }
        _ => unreachable!(),
    }
}

#[inline]
pub fn poly_decompress<const K: usize>(poly: &mut CPoly, bytes: &[u8]) {
    match K {
        2 => {
            // D = 4
            debug_assert_eq!(bytes.len(), 128);
            #[allow(unsafe_code)]
            unsafe {
                bindings_512::pqcrystals_kyber512_ref_poly_decompress(
                    poly.as_mut_ptr() as _,
                    bytes.as_ptr() as _,
                );
            }
        }
        3 => {
            // D = 4
            debug_assert_eq!(bytes.len(), 128);
            #[allow(unsafe_code)]
            unsafe {
                bindings_768::pqcrystals_kyber768_ref_poly_decompress(
                    poly.as_mut_ptr() as _,
                    bytes.as_ptr() as _,
                );
            }
        }
        4 => {
            // D = 5
            debug_assert_eq!(bytes.len(), 160);
            #[allow(unsafe_code)]
            unsafe {
                bindings_1024::pqcrystals_kyber1024_ref_poly_decompress(
                    poly.as_mut_ptr() as _,
                    bytes.as_ptr() as _,
                );
            }
        }
        _ => unreachable!(),
    }
}

#[inline]
pub fn polyvec_decompress<const K: usize>(poly: &mut CPolyVec<K>, bytes: &[u8]) {
    match K {
        2 => {
            const D: usize = 10;
            debug_assert_eq!(bytes.len(), 32 * D * K);
            #[allow(unsafe_code)]
            unsafe {
                bindings_512::pqcrystals_kyber512_ref_polyvec_decompress(
                    poly.as_mut_ptr() as _,
                    bytes.as_ptr() as _,
                );
            }
        }
        3 => {
            const D: usize = 10;
            debug_assert_eq!(bytes.len(), 32 * D * K);
            #[allow(unsafe_code)]
            unsafe {
                bindings_768::pqcrystals_kyber768_ref_polyvec_decompress(
                    poly.as_mut_ptr() as _,
                    bytes.as_ptr() as _,
                );
            }
        }
        4 => {
            const D: usize = 11;
            debug_assert_eq!(bytes.len(), 32 * D * K);
            #[allow(unsafe_code)]
            unsafe {
                bindings_1024::pqcrystals_kyber1024_ref_polyvec_decompress(
                    poly.as_mut_ptr() as _,
                    bytes.as_ptr() as _,
                );
            }
        }
        _ => unreachable!(),
    }
}
#[inline]
pub fn poly_cbd_eta_eq_2(r: &mut CPoly, buf: &[u8; 2 * KYBER_N / 4]) {
    debug_assert_eq!(bindings_512::KYBER_ETA2, 2);
    #[allow(unsafe_code)]
    unsafe {
        bindings_512::pqcrystals_kyber512_ref_poly_cbd_eta2(r.as_mut_ptr() as *mut _, buf.as_ptr());
    }
}

#[inline]
pub fn poly_cbd_eta_eq_3(r: &mut CPoly, buf: &[u8; 3 * KYBER_N / 4]) {
    debug_assert_eq!(bindings_512::KYBER_ETA1, 3);
    #[allow(unsafe_code)]
    unsafe {
        bindings_512::pqcrystals_kyber512_ref_poly_cbd_eta1(r.as_mut_ptr() as *mut _, buf.as_ptr());
    }
}

#[inline]
pub fn poly_getnoise_eta_eq_2(poly: &mut CPoly, seed: &[u8; SEEDBYTES], nonce: u8) {
    debug_assert_eq!(bindings_512::KYBER_ETA2, 2);
    #[allow(unsafe_code)]
    unsafe {
        bindings_512::pqcrystals_kyber512_ref_poly_getnoise_eta2(
            poly.as_mut_ptr() as *mut _,
            seed.as_ptr(),
            nonce,
        );
    }
}

#[inline]
pub fn poly_getnoise_eta_eq_3(poly: &mut CPoly, seed: &[u8; SEEDBYTES], nonce: u8) {
    debug_assert_eq!(bindings_512::KYBER_ETA1, 3);
    #[allow(unsafe_code)]
    unsafe {
        bindings_512::pqcrystals_kyber512_ref_poly_getnoise_eta1(
            poly.as_mut_ptr() as *mut _,
            seed.as_ptr(),
            nonce,
        );
    }
}

pub fn indcpa_keypair<const K: usize>(pk: &mut [u8], sk: &mut [u8]) {
    assert_eq!(sk.len(), KYBER_POLYBYTES * K);
    assert_eq!(pk.len(), KYBER_POLYBYTES * K + SEEDBYTES);
    match K {
        2 => {
            #[allow(unsafe_code)]
            unsafe {
                bindings_512::pqcrystals_kyber512_ref_indcpa_keypair(
                    pk.as_mut_ptr() as _,
                    sk.as_mut_ptr() as _,
                );
            }
        }
        3 => {
            #[allow(unsafe_code)]
            unsafe {
                bindings_768::pqcrystals_kyber768_ref_indcpa_keypair(
                    pk.as_mut_ptr() as _,
                    sk.as_mut_ptr() as _,
                );
            }
        }
        4 => {
            #[allow(unsafe_code)]
            unsafe {
                bindings_1024::pqcrystals_kyber1024_ref_indcpa_keypair(
                    pk.as_mut_ptr() as _,
                    sk.as_mut_ptr() as _,
                );
            }
        }
        _ => unreachable!(),
    }
}

pub fn indcpa_enc<const K: usize>(ct: &mut [u8], m: &[u8; 32], pk: &[u8], coins: &[u8; 32]) {
    assert_eq!(pk.len(), KYBER_POLYBYTES * K + SEEDBYTES);
    match K {
        2 => {
            #[allow(unsafe_code)]
            unsafe {
                bindings_512::pqcrystals_kyber512_ref_indcpa_enc(
                    ct.as_mut_ptr() as _,
                    m.as_ptr() as _,
                    pk.as_ptr() as _,
                    coins.as_ptr() as _,
                );
            }
        }
        3 => {
            #[allow(unsafe_code)]
            unsafe {
                bindings_768::pqcrystals_kyber768_ref_indcpa_enc(
                    ct.as_mut_ptr() as _,
                    m.as_ptr() as _,
                    pk.as_ptr() as _,
                    coins.as_ptr() as _,
                );
            }
        }
        4 => {
            #[allow(unsafe_code)]
            unsafe {
                bindings_1024::pqcrystals_kyber1024_ref_indcpa_enc(
                    ct.as_mut_ptr() as _,
                    m.as_ptr() as _,
                    pk.as_ptr() as _,
                    coins.as_ptr() as _,
                );
            }
        }
        _ => unreachable!(),
    }
}

pub fn indcpa_dec<const K: usize>(m: &mut [u8; 32], ct: &[u8], sk: &[[u8; KYBER_POLYBYTES]; K]) {
    // assert_eq!(sk.len(), KYBER_POLYBYTES * K);
    match K {
        2 => {
            #[allow(unsafe_code)]
            unsafe {
                bindings_512::pqcrystals_kyber512_ref_indcpa_dec(
                    m.as_mut_ptr() as _,
                    ct.as_ptr() as _,
                    sk.as_ptr() as _,
                );
            }
        }
        3 => {
            #[allow(unsafe_code)]
            unsafe {
                bindings_768::pqcrystals_kyber768_ref_indcpa_dec(
                    m.as_mut_ptr() as _,
                    ct.as_ptr() as _,
                    sk.as_ptr() as _,
                );
            }
        }
        4 => {
            #[allow(unsafe_code)]
            unsafe {
                bindings_1024::pqcrystals_kyber1024_ref_indcpa_dec(
                    m.as_mut_ptr() as _,
                    ct.as_ptr() as _,
                    sk.as_ptr() as _,
                );
            }
        }
        _ => unreachable!(),
    }
}
