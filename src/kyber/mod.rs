pub mod ciphertext;
pub mod kem;
pub mod pke;

pub use ciphertext::*;
pub use kem::*;
pub use pke::*;

use crate::keccak::fips202::{HasParams, Shake128, Shake256};
use crate::keccak::KeccakParams;
use crate::poly::kyber::KYBER_N;

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
