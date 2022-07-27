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

pub type CPoly = [i16; KYBER_N];

pub fn ntt(poly: &mut CPoly) {
    #[allow(unsafe_code)]
    unsafe {
        bindings_512::pqcrystals_kyber512_ref_poly_ntt(poly.as_mut_ptr() as *mut _);
    }
}

pub fn polyvec_ntt<const K: usize>(pv: &mut [CPoly; K]) {
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

pub fn polyvec_invntt_tomont<const K: usize>(pv: &mut [CPoly; K]) {
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

#[inline(always)]
pub fn poly_reduce(poly: &mut CPoly) {
    #[allow(unsafe_code)]
    unsafe {
        bindings_512::pqcrystals_kyber512_ref_poly_reduce(poly.as_mut_ptr() as *mut _);
    }
}

#[inline(always)]
pub fn basemul(r: &mut [i16; 2], a: &[i16; 2], b: &[i16; 2], zeta: i16) {
    #[allow(unsafe_code)]
    unsafe {
        bindings_512::pqcrystals_kyber512_ref_basemul(r.as_mut_ptr(), a.as_ptr(), b.as_ptr(), zeta);
    }
}

#[inline(always)]
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
