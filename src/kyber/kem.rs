use super::{CPASecretKey, PublicKey};
use crate::{
    keccak::fips202::{Digest, Sha3_256},
    kyber::KYBER_SSBYTES,
};

pub struct SecretKey<const K: usize> {
    pub cpa_sk: CPASecretKey<K>,
    pub pk: PublicKey<K>,
    pub h_pk: [u8; Sha3_256::DIGEST_BYTES],
    pub z: [u8; KYBER_SSBYTES],
}

trait Kem {}

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
