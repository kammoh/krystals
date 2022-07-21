// use crate::unsafe_utils::*;
// use crate::params::KYBER_SYMBYTES;
// // use sha3::digest::ExtendableOutput;
// use digest::ExtendableOutput;
// use digest::Update;
// use digest::XofReader;

// const fn bits_to_rate(bits: usize) -> usize {
//     200 - bits / 4
// }

// pub trait XofBase {
//     const RATE_BYTES: usize;
//     // fn absorb(&mut self, buf: &[u8]);
//     fn absorb(&mut self, seed: &[u8; KYBER_SYMBYTES], i: u8, j: u8);
//     fn squeeze(&mut self, buf: &mut [u8]);
//     fn new() -> Self;
// }

// pub struct Shake128Xof {
//     hasher: Shake128,
// }

// // pub type Xof = Shake128Xof;

// impl XofBase for Shake128Xof {
//     const RATE_BYTES: usize = bits_to_rate(128);
//     fn absorb(&mut self, seed: &[u8; KYBER_SYMBYTES], i: u8, j: u8) {
//         self.hasher.update(seed);
//         self.hasher.update(&[i, j]);
//     }
//     fn squeeze(&mut self, buf: &mut [u8]) {
//         println!("Shake128Xof squeeze {} bytes", buf.len());
//         self.hasher.finalize_xof_dirty().read(buf); // FIXME finalize_xof_dirty copies state, need to re-implement sha3?
//     }
//     fn new() -> Self {
//         Shake128Xof {
//             hasher: Shake128::default(),
//         }
//     }
// }

// pub struct TinyShakeXof {
//     hasher: tiny_keccak::Shake,
// }
// // pub type Xof = TinyShakeXof;

// impl XofBase for TinyShakeXof {
//     const RATE_BYTES: usize = bits_to_rate(128);
//     fn absorb(&mut self, seed: &[u8; KYBER_SYMBYTES], i: u8, j: u8) {
//         println!("TinyShakeXof absorb {} {} {}", encode_hex(seed), i, j);
//         self.hasher.update(seed);
//         self.hasher.update(&[i, j]);
//     }
//     fn squeeze(&mut self, buf: &mut [u8]) {
//         println!("TinyShakeXof squeeze {} bytes", buf.len());
//         self.hasher.squeeze(buf); // FIXME finalize_xof_dirty copies state, need to re-implement sha3?
//     }
//     fn new() -> Self {
//         TinyShakeXof {
//             hasher: tiny_keccak::Shake::v128(),
//         }
//     }
// }

// pub struct CustomXof {
//     state: KeccakState,
// }
// pub type Xof = CustomXof;

// impl XofBase for CustomXof {
//     const RATE_BYTES: usize = bits_to_rate(128);
//     fn absorb(&mut self, seed: &[u8; KYBER_SYMBYTES], i: u8, j: u8) {
//         let mut extseed = [0u8; KYBER_SYMBYTES + 2]; // TODO keep the buffer
//         extseed[..KYBER_SYMBYTES].copy_from_slice(seed);
//         extseed[KYBER_SYMBYTES] = i;
//         extseed[KYBER_SYMBYTES + 1] = j;
//         shake128_absorb_once(&mut self.state, &extseed, KYBER_SYMBYTES + 2);
//     }
//     fn squeeze(&mut self, buf: &mut [u8]) {
//         shake128_squeezeblocks(buf, buf.len() / Self::RATE_BYTES, &mut self.state);
//     }
//     fn new() -> Self {
//         CustomXof {
//             state: KeccakState::new(),
//         }
//     }
// }
