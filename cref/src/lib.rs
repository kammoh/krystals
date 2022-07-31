#![cfg_attr(not(feature = "std"), no_std)]

pub mod dilithium;
pub mod kyber;
pub mod randombytes;

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {}
