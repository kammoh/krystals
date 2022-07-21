// #![no_std]
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod field;
pub(crate) mod indcpa;
pub mod keccak;
mod kem;
pub mod macros;
pub mod params;
pub mod poly;
pub mod polymat;
pub mod polyvec;
pub(crate) mod unsafe_utils;
pub(crate) mod utils;
pub use kem::*;
