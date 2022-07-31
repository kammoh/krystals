use core::ops::SubAssign;

use secrecy::{ExposeSecret, Secret};

use crate::ciphertext::{Ciphertext, CompressCiphertext, CompressedCiphertex};
use crate::keccak::fips202::{Digest, Sha3_512};
use crate::poly::kyber::{KyberPoly, Prf, MSG_BYTES, NOISE_SEED_BYTES};
use crate::poly::{Polynomial, UNIFORM_SEED_BYTES};
use crate::polyvec::*;
use crate::utils::split::ArraySplitter;
use crate::CPASecretKey;
use crate::PublicKey;

// API?
pub const KYBER_SSBYTES: usize = MSG_BYTES;
pub const KYBER_SYMBYTES: usize = 32;

pub fn keypair<const K: usize>(
    entropy: &[u8; KYBER_SYMBYTES],
    sk: &mut CPASecretKey<K>,
    pk: &mut PublicKey<K>,
) {
    let mut buf = [0u8; UNIFORM_SEED_BYTES + NOISE_SEED_BYTES];

    let mut hash_g = Sha3_512::default();
    hash_g.digest(entropy, &mut buf);

    let (public_seed, noise_seed): (&[u8; UNIFORM_SEED_BYTES], &[u8; NOISE_SEED_BYTES]) =
        buf.dissect_ref();

    pk.seed = *public_seed; // copy_from_slice(public_seed) ???

    let mut prf = Prf::default();

    let mut a_i = KyberPolyVec::<K>::default();

    let mut skpv = KyberPolyVec::<K>::default();
    skpv.getnoise_eta1(&mut prf, noise_seed, 0);
    skpv.ntt_and_reduce();
    skpv.into_bytes(sk.bytes_mut());

    // if we can do getnoise_eta1 and/or ntt in parallel (for K polys at once), then this would be faster:
    // let mut e = KyberPolyVec::<K>::default();
    // e.getnoise_eta1(&mut prf, noise_seed, K as u8);
    // e.ntt(); //  C ref: does an extra e.reduce() (which is not needed)

    // otherwise Maybe this is ok (eliminates K-1 poly allocations)
    let mut e_i = KyberPoly::default();

    let mut pkpv = KyberPolyVec::<K>::default();

    for (i, pk_poly) in pkpv.as_mut().iter_mut().enumerate() {
        a_i.uniform_xof::<false>(public_seed, i as u8);

        pk_poly.vector_mul_acc(&a_i, &skpv);
        // C ref does an extra  pk_poly.reduce() which is not needed

        e_i.getnoise_eta1::<K>(&mut prf, noise_seed, (K + i) as u8);
        e_i.ntt();

        pk_poly.into_montgomery();
        (*pk_poly) += &e_i;
    }

    pkpv.reduce();
    pkpv.into_bytes(&mut pk.bytes);
}

trait SecLevel {
    const K: usize;
    type CT: CompressedCiphertex;
}
struct L1;
impl SecLevel for L1 {
    const K: usize = 2;
    type CT = Ciphertext<4, 10, 2, 32, KyberPoly>;
}

pub fn encrypt<CT, const K: usize>(
    msg: &[u8; MSG_BYTES],
    pk: &PublicKey<K>,
    coins: &[u8; NOISE_SEED_BYTES],
    ct: &mut CT,
) where
    CT: CompressCiphertext<K, PolyType = KyberPoly, PolyVecType = KyberPolyVec<K>>,
{
    let mut prf = Prf::default();

    let mut sp = KyberPolyVec::<K>::default();
    sp.getnoise_eta1(&mut prf, coins, 0);
    sp.ntt_and_reduce();

    let mut b = KyberPolyVec::<K>::default();
    let mut a_i = KyberPolyVec::<K>::default();
    for (i, b_poly) in b.as_mut().iter_mut().enumerate() {
        a_i.uniform_xof::<true>(&pk.seed, i as u8);
        b_poly.vector_mul_acc(&a_i, &sp);
    }
    b.inv_ntt_tomont();

    let mut ep = KyberPolyVec::<K>::default();
    ep.getnoise_eta2(&mut prf, coins, K as u8);
    b += &ep;
    b.reduce();
    ct.compress_polyvec(&b);

    let pkpv = KyberPolyVec::from_bytes(&pk.bytes);
    let mut v = KyberPoly::default();
    v.vector_mul_acc(&pkpv, &sp);
    v.inv_ntt();
    let mut epp = KyberPoly::default();
    epp.getnoise_eta2(&mut prf, coins, 2 * K as u8);
    v += &epp;
    v += &KyberPoly::from_message(msg);
    ct.compress_poly(&v);
}

pub fn decrypt<CT, const K: usize>(ct: &CT, sk: &CPASecretKey<K>, msg: &mut [u8; MSG_BYTES])
where
    CT: CompressCiphertext<K, PolyType = KyberPoly, PolyVecType = KyberPolyVec<K>>,
{
    let mut b = KyberPolyVec::<K>::default();
    ct.decompress_polyvec(&mut b);
    b.ntt();

    let skpv = KyberPolyVec::<K>::from_bytes(&sk.bytes());
    let mut mp = KyberPoly::default();
    b.basemul_acc(&skpv, &mut mp);
    mp.inv_ntt();

    let mut v = KyberPoly::default();
    ct.decompress_poly(&mut v);
    mp -= &v;

    mp.into_message(msg);
}

pub type KyberCiphertextL1 = Ciphertext<4, 10, 2, 32, KyberPoly>;
pub type KyberCiphertextL2 = Ciphertext<4, 10, 3, 32, KyberPoly>;
pub type KyberCiphertextL3 = Ciphertext<5, 11, 4, 32, KyberPoly>;

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec::Vec;
    use std::*;

    use crystals_cref::kyber as cref;
    use crystals_cref::randombytes;
    use rand::Rng;
    use rand::RngCore;

    use crate::ciphertext::*;
    use crate::poly::kyber::kyber_ciphertext_bytes;
    use crate::poly::kyber::poly_compressed_bytes_for_k;
    use crate::poly::kyber::polyvec_compressed_bytes_for_k;
    use crate::poly::kyber::POLYBYTES;
    use crate::utils::flatten::FlattenSlice;

    use super::*;

    fn test_keypair_vs_ref<const K: usize>() {
        let mut rng = rand::thread_rng();

        let mut entropy = [0u8; KYBER_SYMBYTES];
        let mut sk = CPASecretKey::<K>::default();
        let mut pk = PublicKey::<K>::default();

        let mut pk_ref = vec![0u8; (POLYBYTES * K) + UNIFORM_SEED_BYTES];
        let mut sk_ref = vec![0u8; POLYBYTES * K];

        for test in 0..16_000 / (K * K) {
            rng.fill(entropy.as_mut());
            randombytes::randombytes_push_to_queue(&entropy);

            keypair(&entropy, &mut sk, &mut pk);

            cref::indcpa_keypair::<K>(&mut pk_ref, sk_ref.as_mut_slice());

            assert_eq!(pk.seed, pk_ref[POLYBYTES * K..]);
            assert_eq!(
                sk.bytes().as_slice().flatten_slice(),
                sk_ref,
                "SK failed K={K} test#={test} entropy={entropy:?}"
            );
            assert_eq!(
                pk.bytes.as_slice().flatten_slice(),
                &pk_ref[..POLYBYTES * K],
                "PK failed K={K} test#={test} entropy={entropy:?}"
            );
        }
    }

    #[test]
    fn keypair_vs_ref_2() {
        test_keypair_vs_ref::<2>();
    }
    #[test]
    fn keypair_vs_ref_3() {
        test_keypair_vs_ref::<3>();
    }
    #[test]
    fn keypair_vs_ref_4() {
        test_keypair_vs_ref::<4>();
    }

    fn test_encrypt_vs_ref<const K: usize>() {
        let mut rng = rand::thread_rng();

        let mut entropy = [0u8; NOISE_SEED_BYTES];
        rng.fill(entropy.as_mut());
        let mut sk = CPASecretKey::<K>::default();
        let mut pk = PublicKey::<K>::default();
        keypair(&entropy, &mut sk, &mut pk);

        let mut msg = [0u8; MSG_BYTES];
        let mut coins = [0u8; NOISE_SEED_BYTES];

        for _test in 0..1_000 {
            rng.fill(msg.as_mut());
            rng.fill(coins.as_mut());

            let mut ct_ref = vec![0u8; kyber_ciphertext_bytes::<K>()];
            let mut pk_ref = Vec::new();

            for b in pk.bytes {
                pk_ref.extend_from_slice(&b);
            }
            pk_ref.extend_from_slice(&pk.seed);
            cref::indcpa_enc::<K>(ct_ref.as_mut(), &msg, &pk_ref, &coins);

            match K {
                #![allow(unsafe_code)]
                2 => {
                    let pk_x = unsafe { &*(&pk as *const _ as *const _) };
                    let mut ct = KyberCiphertextL1::default();
                    encrypt(&msg, pk_x, &coins, &mut ct);
                    println!("ct: {:?}\n", ct);
                    assert_eq!(
                        ct.polyvec_bytes(),
                        &ct_ref[..polyvec_compressed_bytes_for_k::<K>()]
                    );
                    assert_eq!(
                        ct.poly_bytes(),
                        &ct_ref[polyvec_compressed_bytes_for_k::<K>()..]
                    );
                }
                3 => {
                    let pk_x = unsafe { &*(&pk as *const _ as *const _) };
                    let mut ct = KyberCiphertextL2::default();
                    encrypt(&msg, pk_x, &coins, &mut ct);
                    assert_eq!(
                        ct.polyvec_bytes(),
                        &ct_ref[..polyvec_compressed_bytes_for_k::<K>()]
                    );
                    assert_eq!(
                        ct.poly_bytes(),
                        &ct_ref[polyvec_compressed_bytes_for_k::<K>()..]
                    );
                }
                4 => {
                    let pk_x = unsafe { &*(&pk as *const _ as *const _) };
                    let mut ct = KyberCiphertextL3::default();
                    encrypt(&msg, pk_x, &coins, &mut ct);
                    assert_eq!(
                        ct.polyvec_bytes(),
                        &ct_ref[..polyvec_compressed_bytes_for_k::<K>()]
                    );
                    assert_eq!(
                        ct.poly_bytes(),
                        &ct_ref[polyvec_compressed_bytes_for_k::<K>()..]
                    );
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn encrypt_vs_ref_2() {
        test_encrypt_vs_ref::<2>();
    }
    #[test]
    fn encrypt_vs_ref_3() {
        test_encrypt_vs_ref::<3>();
    }
    #[test]
    fn encrypt_vs_ref_4() {
        test_encrypt_vs_ref::<4>();
    }

    fn test_decrypt_vs_ref<const K: usize>() {
        let mut rng = rand::thread_rng();

        let mut entropy = [0u8; NOISE_SEED_BYTES];
        rng.fill(entropy.as_mut());
        let mut sk = CPASecretKey::<K>::default();
        let mut pk = PublicKey::<K>::default();
        keypair(&entropy, &mut sk, &mut pk);

        let mut msg = [0u8; MSG_BYTES];
        let mut msg_ref = [0u8; MSG_BYTES];

        let mut ct_vec =
            vec![0; poly_compressed_bytes_for_k::<K>() + polyvec_compressed_bytes_for_k::<K>()];

        let ct = SliceCipherText::<K>(&mut ct_vec);

        for _test in 0..4_000 / K {
            rng.fill_bytes(&mut ct.0.as_mut());

            cref::indcpa_dec::<K>(&mut msg_ref, &ct.0, &sk.bytes());
            decrypt(&ct, &sk, &mut msg);
            assert_eq!(msg, msg_ref);
        }
    }

    #[test]
    fn decrypt_vs_ref_2() {
        test_decrypt_vs_ref::<2>();
    }
    #[test]
    fn decrypt_vs_ref_3() {
        test_decrypt_vs_ref::<3>();
    }
    #[test]
    fn decrypt_vs_ref_4() {
        test_decrypt_vs_ref::<4>();
    }
}
