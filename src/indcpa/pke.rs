use crate::params::*;
use crate::poly::kyber::KYBER_POLYBYTES;
use crate::poly::kyber::KyberPoly;
use crate::poly::Polynomial;
use crate::polyvec::*;
use crate::unsafe_utils::*;
use crate::CPASecretKey;
use crate::CipherText;
use crate::PublicKey;
use rand::RngCore;
// use sha3::digest::generic_array::GenericArray;
// use sha3::digest::FixedOutput;
// use sha3::Digest;

pub fn keypair<R, const K: usize>(
    rng: &mut R,
) -> Result<(PublicKey<K>, CPASecretKey<K>), KyberError>
where
    R: RngCore,
{
    // let mut entropy = [0u8; KYBER_SYMBYTES];
    // let mut buf = [0u8; 2 * KYBER_SYMBYTES];

    // rng.try_fill_bytes(&mut entropy)
    //     .or(Err(KyberError::RngFailure))?;

    // let mut hash_g = Sha3_512::new();

    // hash_g.update(&entropy);

    // hash_g.finalize_into(GenericArray::from_mut_slice(&mut buf));

    // let (publicseed, noiseseed) = (&buf).split::<KYBER_SYMBYTES, KYBER_SYMBYTES>();

    // // assert!(publicseed.len() == KYBER_SYMBYTES && noiseseed.len() == KYBER_SYMBYTES);

    // let a = gen_matrix::<K>(publicseed, false);

    // let mut prf = Shake256::default();

    // let mut skpv: PolyVec::<KYBER_N, K>::getnoise_eta1(noiseseed, 0);
    // let mut e: PolyVec<KYBER_N, K> = prf.polyvec_getnoise_eta1(noiseseed, K as u8);

    // skpv.ntt();
    // e.ntt();

    // let mut pkpv = a.mult_vec(&skpv);

    // pkpv.add_assign(&e);
    // pkpv.reduce();

    let pkpv = PolyVec::<KyberPoly, { KyberPoly::N }, K>::default();
    let skpv = PolyVec::<KyberPoly, { KyberPoly::N }, K>::default();
    let publicseed = &[0u8; KYBER_SYMBYTES];

    let mut pk = PublicKey {
        bytes: [[0u8; KYBER_POLYBYTES]; K],
        seed: *publicseed,
    };

    pkpv.to_bytes(&mut pk.bytes);

    let mut sk = CPASecretKey {
        bytes: [[0u8; KYBER_POLYBYTES]; K],
    };

    skpv.to_bytes(&mut sk.bytes);

    Ok((pk, sk))
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
