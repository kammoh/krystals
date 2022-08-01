use crate::{
    keccak::fips202::{Digest, Sha3_256},
    pke::KYBER_SSBYTES,
    poly::{kyber::POLYBYTES, UNIFORM_SEED_BYTES},
};

// use super::hash::*;
// use rand::RngCore;

#[derive(Debug)]
pub enum KyberError {
    DecapsFailure, // Re-encapsulated message did not match provided ciphertex. Most probably an invalid ciphertext. Returned by decap.
    RngFailure, // was not able to retrieve required random from RNG. Returned by encap and keypair.
}

pub struct PublicKey<const K: usize> {
    pub bytes: [[u8; POLYBYTES]; K],
    pub seed: [u8; UNIFORM_SEED_BYTES],
}

impl<const K: usize> Default for PublicKey<K> {
    fn default() -> Self {
        Self {
            bytes: [[0; POLYBYTES]; K],
            seed: [0; UNIFORM_SEED_BYTES],
        }
    }
}

pub struct CPASecretKey<const K: usize>([[u8; POLYBYTES]; K]);

impl<const K: usize> CPASecretKey<K> {
    #[inline(always)]
    pub fn bytes(&self) -> &[[u8; POLYBYTES]; K] {
        &self.0
    }

    #[inline(always)]
    pub fn bytes_mut(&mut self) -> &mut [[u8; POLYBYTES]; K] {
        &mut self.0
    }
}

impl<const K: usize> Default for CPASecretKey<K> {
    fn default() -> Self {
        Self([[0; POLYBYTES]; K])
    }
}

pub struct SecretKey<const K: usize> {
    pub cpa_sk: CPASecretKey<K>,
    pub pk: PublicKey<K>,
    pub h_pk: [u8; Sha3_256::DIGEST_BYTES],
    pub z: [u8; KYBER_SSBYTES],
}

// pub fn generate_keys<R: RngCore, const K: usize>(
//     rng: &mut R,
// ) -> Result<(PublicKey<K>, SecretKey<K>), KyberError> {

//     let (pk, cpa_sk) = pke::keypair::<R, K>(rng)?;

//     let mut h_pk = [0u8; KYBER_SYMBYTES];
//     let mut hash_h = HashH::new();
//     hash_h
//         .chain(&(pk.bytes).flatten())
//         .digest(&pk.seed, &mut h_pk);
//     let mut z = [0u8; KYBER_SYMBYTES];
//     rng.fill_bytes(&mut z);
//     Ok((
//         pk.clone(),
//         SecretKey {
//             cpa_sk,
//             pk,
//             h_pk,
//             z,
//         },
//     ))
// }

// // FIXME
// // const KYBER_POLYVECCOMPRESSEDBYTES: usize = 352; // 320, 320, 352
// // const KYBER_POLYCOMPRESSEDBYTES: usize = 160; // 128, 128, 160

// // const KYBER_CIPHERTEXTBYTES: usize = KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES;

pub type CipherText<const KYBER_CIPHERTEXTBYTES: usize> = [u8; KYBER_CIPHERTEXTBYTES]; // FIXME


trait Kem {

}

// pub fn encapsulate<R: RngCore, const K: usize, const KYBER_CIPHERTEXTBYTES: usize>(
//     pk: &PublicKey<K>,
//     rng: &mut R,
// ) -> Result<(CipherText<KYBER_CIPHERTEXTBYTES>, SharedSecret), KyberError> {
//     let mut ss = [0u8; KYBER_SSBYTES];

//     let mut kr = [0u8; 2 * KYBER_SYMBYTES];
//     let mut rand_buf = [0u8; KYBER_SYMBYTES];

//     let mut hash_h = HashH::new();
//     let mut hash_g = HashG::new();
//     let mut kdf = Kdf::new();

//     rng.try_fill_bytes(&mut rand_buf)
//     .or(Err(KyberError::RngFailure))?;

//     let mut buf = [0u8; 2 * KYBER_SYMBYTES];
//     let (buf_lo, buf_hi) = buf.split_mut::<32, 32>();
//     hash_h.digest(&rand_buf, buf_hi);

//     // Multitarget countermeasure for coins + contributory KEM
//     hash_h
//         .chain(&pk.bytes.flatten())
//         .digest(&pk.seed, buf_lo);
//     hash_g.digest(&buf, &mut kr);

//     let (msg, _) = buf.split::<32, 32>();
//     let (_, coins) = kr.split_mut::<32, 32>();

//     let ct = pke::encrypt(msg, &pk, coins);

//     // overwrite coins in kr with H(c)
//     hash_h.digest(&ct, coins);

//     // hash concatenation of pre-k and H(c) to k
//     kdf.digest(&kr, &mut ss);

//     Ok((ct, ss))
// }
