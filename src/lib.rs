#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod field;
pub mod keccak;
pub mod kem;
pub mod macros;
pub mod params; // FIXME
pub mod pke;
pub mod poly;
pub mod polymat;
pub mod polyvec;
pub(crate) mod unsafe_utils;
pub(crate) mod utils;
pub use kem::*;
