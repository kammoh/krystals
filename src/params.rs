use crate::{
    poly::{kyber::KyberPoly, Polynomial},
    polyvec::PolyVec,
};

// API?
pub const KYBER_SSBYTES: usize = 32;
pub const KYBER_SYMBYTES: usize = 32;

pub trait KyberParams {
    type PV;
    type PolyVecCompressed;
    // const POLYVEC_COMPRESSED_BYTES: usize;
    const POLY_COMPRESSED_BYTES: usize;
    const K: usize;
}

pub struct Params<const K0: usize>;

impl KyberParams for Params<2> {
    const K: usize = 2;
    type PV = PolyVec<KyberPoly, { KyberPoly::N }, { Self::K }>;
    // const POLYVEC_COMPRESSED_BYTES: usize = Self::K * 320;
    type PolyVecCompressed = [u8; Self::K * 320];
    const POLY_COMPRESSED_BYTES: usize = 128;
}

impl KyberParams for Params<3> {
    const K: usize = 3;
    type PV = PolyVec<KyberPoly, { KyberPoly::N }, { Self::K }>;
    // const POLYVEC_COMPRESSED_BYTES: usize = Self::K * 320;
    type PolyVecCompressed = [u8; Self::K * 320];
    const POLY_COMPRESSED_BYTES: usize = 128;
}
