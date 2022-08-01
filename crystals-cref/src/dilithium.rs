mod bindings_2 {
    #![allow(unsafe_code)]
    #![allow(warnings)]
    extern crate std;
    include!(concat!(env!("OUT_DIR"), "/dilithium2_bindings.rs"));
}

mod bindings_3 {
    #![allow(unsafe_code)]
    #![allow(warnings)]
    extern crate std;
    include!(concat!(env!("OUT_DIR"), "/dilithium3_bindings.rs"));
}

mod bindings_5 {
    #![allow(unsafe_code)]
    #![allow(warnings)]
    extern crate std;
    include!(concat!(env!("OUT_DIR"), "/dilithium5_bindings.rs"));
}

const DILITHIUM_N: usize = bindings_2::N as usize;
const SEEDBYTES: usize = bindings_2::SEEDBYTES as usize;

pub type CPoly = [i32; DILITHIUM_N];

#[inline(always)]
pub fn ntt(poly: &mut CPoly) {
    #[allow(unsafe_code)]
    unsafe {
        bindings_2::pqcrystals_dilithium2_ref_poly_ntt(poly.as_mut_ptr() as *mut _);
    }
}

#[inline(always)]
pub fn inv_ntt(poly: &mut CPoly) {
    #[allow(unsafe_code)]
    unsafe {
        bindings_2::pqcrystals_dilithium2_ref_poly_invntt_tomont(poly.as_mut_ptr() as *mut _);
    }
}

#[inline(always)]
pub fn uniform(poly: &mut CPoly, seed: &[u8; SEEDBYTES], nonce: u16) {
    #[allow(unsafe_code)]
    unsafe {
        bindings_2::pqcrystals_dilithium2_ref_poly_uniform(
            poly.as_mut_ptr() as *mut _,
            seed as *const _,
            nonce,
        );
    }
}

#[inline(always)]
pub fn poly_pointwise_montgomery(r: &mut CPoly, a: &CPoly, b: &CPoly) {
    #[allow(unsafe_code)]
    unsafe {
        bindings_2::pqcrystals_dilithium2_ref_poly_pointwise_montgomery(
            r.as_mut_ptr() as _,
            a.as_ptr() as _,
            b.as_ptr() as _,
        );
    }
}

#[inline(always)]
pub fn polyveck_ntt<const K: usize>(pv: &mut [CPoly; K]) {
    #![allow(unsafe_code)]
    match K {
        4 => unsafe {
            bindings_2::pqcrystals_dilithium2_ref_polyveck_ntt(pv.as_mut_ptr() as *mut _);
        },
        6 => unsafe {
            bindings_3::pqcrystals_dilithium3_ref_polyveck_ntt(pv.as_mut_ptr() as *mut _);
        },
        8 => unsafe {
            bindings_5::pqcrystals_dilithium5_ref_polyveck_ntt(pv.as_mut_ptr() as *mut _);
        },
        _ => unreachable!(),
    }
}

#[inline(always)]
pub fn polyveck_invntt_tomont<const K: usize>(pv: &mut [CPoly; K]) {
    #![allow(unsafe_code)]
    match K {
        4 => unsafe {
            bindings_2::pqcrystals_dilithium2_ref_polyveck_invntt_tomont(pv.as_mut_ptr() as *mut _);
        },
        6 => unsafe {
            bindings_3::pqcrystals_dilithium3_ref_polyveck_invntt_tomont(pv.as_mut_ptr() as *mut _);
        },
        8 => unsafe {
            bindings_5::pqcrystals_dilithium5_ref_polyveck_invntt_tomont(pv.as_mut_ptr() as *mut _);
        },
        _ => unreachable!(),
    }
}
