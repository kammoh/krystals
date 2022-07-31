#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;

#[macro_use]
extern crate static_assertions;

/// A workaround for all the types we need from the `std`, `core`, and `alloc`
/// crates, avoiding elaborate import wrangling having to happen in every module.
/// Based on https://github.com/serde-rs/serde
mod lib {
    mod core {
        #[cfg(not(feature = "std"))]
        pub use core::*;
        #[cfg(feature = "std")]
        pub use std::*;
    }

    pub use self::core::cell::{Cell, RefCell};
    pub use self::core::clone::{self, Clone};
    pub use self::core::convert::{self, From, Into};
    pub use self::core::default::{self, Default};
    pub use self::core::fmt::{self, Debug, Display};
    pub use self::core::marker::{self, PhantomData};
    pub use self::core::num::Wrapping;
    pub use self::core::ops;
    pub use self::core::option::{self, Option};
    pub use self::core::result::{self, Result};
    pub use self::core::{cmp, iter, mem, num, ptr, slice, str};
    pub use self::core::{i16, i32, i64, i8, isize};
    pub use self::core::{u16, u32, u64, u8, usize};

    #[cfg(all(feature = "alloc", not(feature = "std")))]
    pub use alloc::borrow::{Cow, ToOwned};
    #[cfg(feature = "std")]
    pub use std::borrow::{Cow, ToOwned};
}

////////////////////////////////////////////////////////////////////////////////

#[macro_use]
mod macros;

mod field;
mod params;
mod utils; // FIXME

// needed for benchmarks
#[cfg(not(feature = "pub_internals"))]
mod poly;
#[cfg(feature = "pub_internals")]
pub mod poly;
#[cfg(not(feature = "pub_internals"))]
mod polymat;
#[cfg(feature = "pub_internals")]
pub mod polymat;
#[cfg(not(feature = "pub_internals"))]
mod polyvec;
#[cfg(feature = "pub_internals")]
pub mod polyvec;

pub mod ciphertext;
pub mod keccak;
pub mod kem;
pub mod pke;

pub use kem::*;
