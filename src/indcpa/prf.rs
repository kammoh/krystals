// use crate::params::KYBER_N;
// use crate::params::KYBER_SYMBYTES;

// use super::cbd::*;
// use super::poly::*;
// use super::polyvec::*;

pub trait Prf {
    fn prf<const BYTES: usize>(&mut self, buf: &mut [u8; BYTES], seed: &[u8], nonce: u8);
}

// impl Prf for Shake256 {
//     fn prf<const BYTES: usize>(&mut self, buf: &mut [u8; BYTES], seed: &[u8], nonce: u8) {
//         self.update(seed);
//         self.update(&[nonce]);
//         self.finalize_xof_reset().read(buf);
//     }

//     // fn polyvec_getnoise_eta1<const K: usize>(
//     //     &mut self,
//     //     seed: &[u8; KYBER_SYMBYTES],
//     //     mut nonce: u8,
//     // ) -> PolyVec<K> {
//     //     if K == 2 {
//     //         let mut r = PolyVec::default();
//     //         let mut buf = [0u8; 3 * KYBER_N / 4]; // TODO avoid double initialization?
//     //         for i in 0..2 {
//     //             self.get_bytes_to(&mut buf, seed, nonce);
//     //             cbd3(&mut r[i].coeffs, &buf);
//     //             nonce += 1;
//     //         }
//     //         r
//     //     } else {
//     //         self.polyvec_getnoise_eta2::<K>(seed, nonce)
//     //     }
//     // }
//     // fn polyvec_getnoise_eta2<const K: usize>(
//     //     &mut self,
//     //     seed: &[u8; KYBER_SYMBYTES],
//     //     mut nonce: u8,
//     // ) -> PolyVec<K> {
//     //     let mut r = PolyVec::default(); // TODO avoid double initialization?
//     //     for i in 0..K {
//     //         self.poly_getnoise_eta2(&mut r.vec[i], seed, nonce);
//     //         nonce += 1;
//     //     }
//     //     r
//     // }

// }
