#![deny(unsafe_code)]
#![no_std]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;

pub(crate) mod utils;

pub mod field;
pub mod keccak;
pub mod kem;
pub mod macros;
pub mod params; // FIXME
pub mod pke;
pub mod poly;
pub mod polymat;
pub mod polyvec;

pub use kem::*;
