use crate::keccak::fips202::Digest;
use crate::keccak::fips202::Sha3_512;
use crate::keccak::fips202::Shake256;
use crate::params::*;
use crate::poly::kyber::KyberPoly;
use crate::poly::kyber::KYBER_POLYBYTES;
use crate::poly::Polynomial;
use crate::polymat::KyberMatrix;
use crate::polyvec::*;
use crate::unsafe_utils::*;
use crate::utils::split::ArraySplitter;
use crate::CPASecretKey;
use crate::CipherText;
use crate::PublicKey;
use rand::RngCore;

pub fn keypair<const K: usize>(
    entropy: &[u8; KYBER_SYMBYTES], pk: &mut PublicKey<K>, sk: &mut CPASecretKey<K>) {
    let mut buf = [0u8; 2 * KYBER_SYMBYTES];
    
    let mut hash_g = Sha3_512::default();
    hash_g.digest(entropy, &mut buf);

    let (public_seed, noise_seed): (&[u8; KYBER_SYMBYTES], &[u8; KYBER_SYMBYTES]) = buf.dissect_ref();

    let mut a_i = KyberPolyVec::<K>::default();

    // let mut prf = Shake256::default();
    // let mut skpv: KyberPolyVec::<K>::getnoise_eta1(&mut prf, noise_seed, 0);
    
    // for i in 0..K {
    //     a_i.uniform(public_seed, i as u8);
        
    //     let mut e_i  = KyberPoly::getnoise_eta1(&mut prf, noise_seed, (K + i) as u8);
    //     a_i.
    // }




    // skpv.ntt();
    // pkpv.ntt();

    // mat_a.mult_vec_acc(&skpv);

    // pkpv.reduce();

    // let pkpv = PolyVec::<KyberPoly, { KyberPoly::N }, K>::default();
    // let skpv = PolyVec::<KyberPoly, { KyberPoly::N }, K>::default();
    // let publicseed = &[0u8; KYBER_SYMBYTES];

    // let mut pk = PublicKey {
    //     bytes: [[0u8; KYBER_POLYBYTES]; K],
    //     seed: *publicseed,
    // };

    // pkpv.to_bytes(&mut pk.bytes);

    // let mut sk = CPASecretKey {
    //     bytes: [[0u8; KYBER_POLYBYTES]; K],
    // };

    // skpv.to_bytes(&mut sk.bytes);

    
}

trait SecLevel {
    const K: usize;
}
struct L1 {}
impl SecLevel for L1 {
    const K: usize = 2;
}

// use generic_array::GenericArray;
// use std::ops::Add;
// // use generic_array::typenum::{Unsigned, Integer, U2, U3, U4};
// use generic_array::typenum::{Integer, U3, U4, Prod, UTerm, B1, B0, Unsigned};
// use core::ops::Mul;
// // const fn k<L:SecLevel> () -> usize {
// //     a:  GenericArray<u8, <U3 as Mul<U2>> >;
// //     2
// // }

// // type X = Prod<N, U3> ;
// struct Foo<N: ArrayLength<u8> + Unsigned > {
//     data: GenericArray<u8, Prod<N, U3> >
// }

fn pack_ciphertext<P, const N: usize, const K: usize, const CT_BYTES: usize>(
    b: &PolyVec<P, N, K>,
    v: &P,
    ct: &mut [u8; CT_BYTES],
) where
    P: Polynomial<N>,
{
    // const KYBER_POLYVECCOMPRESSEDBYTES: usize =
    // K match {
    //     2 => 2
    // }
    // fn kk() -> usize {
    // }
    // let x = match K {
    //     2 => 2 * 320,
    // };
    // const KYBER_POLYVECCOMPRESSEDBYTES =
    // b.compress_to(&mut ct); // [..KYBER_POLYVECCOMPRESSEDBYTES]
    // v.compress_to::<K>(&mut ct); // [KYBER_POLYVECCOMPRESSEDBYTES..]
}

pub fn encrypt<const K: usize, const CT_BYTES: usize>(
    msg: &[u8; KYBER_SYMBYTES],
    pk: &PublicKey<K>,
    coins: &[u8; KYBER_SYMBYTES],
    ct: &mut [u8; CT_BYTES],
) {
    // let mut prf = Shake256::default();

    let pkpv = PolyVec::<KyberPoly, { KyberPoly::N }, K>::from_bytes(&pk.bytes);

    // let k = Poly::from_message(msg);

    // let at = gen_matrix::<K>(&pk.seed, true);

    // let mut sp = PolyVec::<KYBER_N, K>::getnoise_eta1(prf, coins, 0 as u8);
    // let ep = PolyVec::<KYBER_N, K>::getnoise_eta1(coins, K as u8);

    // let epp = Poly::getnoise_eta2(&mut prf, coins, (K + 1) as u8);

    // sp.ntt();

    // let mut b = at.mult_vec(&sp);
    // b.invntt_tomont();

    // let mut v = pkpv * sp;
    // v.inv_ntt();

    // b += &ep;
    // b.reduce();

    // v += &epp;
    // v += &k;
    // v.reduce();

    // pack_ciphertext(&b, &v)
}