use core::ops::{AddAssign, Index, IndexMut};

use rand::{CryptoRng, RngCore};

use crate::{
    keccak::fips202::{CrystalsPrf, CrystalsXof, SpongeOps},
    poly::{
        dilithium::DilithiumPoly,
        kyber::{KyberPoly, Prf, Xof, KYBER_N, NOISE_SEED_BYTES, POLYBYTES, XOF_BLOCK_BYTES},
        Polynomial, UNIFORM_SEED_BYTES,
    },
};

use super::poly::SizedPolynomial;

pub trait PolynomialVector: Default + Sized + Index<usize> + IndexMut<usize> {
    type Poly: Polynomial;
    const K: usize;

    fn ntt(&mut self);
    fn ntt_and_reduce(&mut self);
    fn inv_ntt_tomont(&mut self);

    fn reduce(&mut self);
    fn uniform_xof<const TRANSPOSED: bool>(&mut self, seed: &[u8; UNIFORM_SEED_BYTES], i: u8);

    fn basemul_acc(&self, other: &Self, result: &mut <Self as PolynomialVector>::Poly);
}

#[derive(Debug, Clone, Copy)]
pub struct PolyVec<P, const N: usize, const K: usize>([P; K])
where
    P: Polynomial;

impl<P, const N: usize, const K: usize> Default for PolyVec<P, N, K>
where
    P: Polynomial,
{
    fn default() -> Self {
        PolyVec([P::default(); K])
    }
}

// impl<P, const K: usize> PolynomialVector<K> for PolyVec<P, K>
// where
//     P: PolynomialTrait,
// {
//     type Poly = P;
// }

impl<P, const N: usize, const K: usize> Index<usize> for PolyVec<P, N, K>
where
    P: Polynomial,
{
    type Output = P;
    fn index(&self, i: usize) -> &Self::Output {
        &self.0[i]
    }
}

impl<P, const N: usize, const K: usize> IndexMut<usize> for PolyVec<P, N, K>
where
    P: Polynomial,
{
    fn index_mut(&mut self, i: usize) -> &mut Self::Output {
        &mut self.0[i]
    }
}

impl<P, const N: usize, const K: usize> AsRef<[P; K]> for PolyVec<P, N, K>
where
    P: Polynomial,
{
    #[inline(always)]
    fn as_ref(&self) -> &[P; K] {
        &self.0
    }
}

impl<P, const N: usize, const K: usize> AsMut<[P; K]> for PolyVec<P, N, K>
where
    P: Polynomial,
{
    #[inline(always)]
    fn as_mut(&mut self) -> &mut [P; K] {
        &mut self.0
    }
}

impl<P, const N: usize, const K: usize> PolynomialVector for PolyVec<P, N, K>
where
    P: SizedPolynomial<N>,
{
    const K: usize = K;
    type Poly = P;

    #[inline]
    fn ntt(&mut self) {
        for poly in self {
            poly.ntt();
        }
    }

    #[inline]
    fn ntt_and_reduce(&mut self) {
        for poly in self {
            poly.ntt();
            poly.reduce();
        }
    }

    #[inline]
    fn inv_ntt_tomont(&mut self) {
        for poly in self {
            poly.inv_ntt();
        }
    }

    #[inline]
    fn reduce(&mut self) {
        for poly in self {
            poly.reduce();
        }
    }

    #[inline]
    fn uniform_xof<const TRANSPOSED: bool>(&mut self, seed: &[u8; UNIFORM_SEED_BYTES], i: u8) {
        let mut shake128 = Xof::default();
        let mut xof_out = [0u8; XOF_BLOCK_BYTES];

        for (j, poly) in self.as_mut().iter_mut().enumerate() {
            let (i, j) = if TRANSPOSED {
                (i, j as u8)
            } else {
                (j as u8, i)
            };

            shake128.absorb_xof_with_nonces(seed, i, j);

            let mut ctr = 0;
            while ctr < Self::Poly::NUM_SCALARS {
                shake128.squeeze(&mut xof_out);
                ctr = poly.rej_uniform(ctr, &xof_out);
            }

            debug_assert_eq!(ctr, Self::Poly::NUM_SCALARS);
        }
    }

    fn basemul_acc(&self, other: &Self, result: &mut <Self as PolynomialVector>::Poly) {
        // // TODO: optimize
        for (left, right) in self.into_iter().zip(other) {
            left.pointwise_acc(right, result);
        }
        result.reduce();
    }

    //     #[inline(always)]
    //     pub fn to_mont(&mut self) {
    //         for i in 0..K {
    //             self[i].to_mont();
    //         }
    //     }
}

impl<'a, const N: usize, P, const K: usize> IntoIterator for &'a mut PolyVec<P, N, K>
where
    P: Polynomial,
{
    type Item = &'a mut P;

    type IntoIter = core::slice::IterMut<'a, P>;

    fn into_iter(self) -> Self::IntoIter {
        (*self).as_mut().iter_mut()
    }
}

impl<'a, P, const N: usize, const K: usize> IntoIterator for &'a PolyVec<P, N, K>
where
    P: Polynomial,
{
    type Item = &'a P;

    type IntoIter = core::slice::Iter<'a, P>;

    fn into_iter(self) -> Self::IntoIter {
        (*self).as_ref().iter()
    }
}

impl<P, const N: usize, const K: usize> AddAssign<&Self> for PolyVec<P, N, K>
where
    P: Polynomial,
{
    fn add_assign(&mut self, rhs: &Self) {
        for i in 0..K {
            self[i] += &rhs[i];
        }
    }
}

impl<const N: usize, const K: usize> PolyVec<KyberPoly, N, K> {
    #[inline(always)]
    pub fn new_deserialize(bytes: &[[u8; POLYBYTES]; K]) -> Self {
        let mut pv = Self::default();
        pv.deserialize(bytes);
        pv
    }

    #[inline(always)]
    pub fn deserialize(&mut self, bytes: &[[u8; POLYBYTES]; K]) {
        for (poly, b) in self.into_iter().zip(bytes) {
            poly.deserialize(b);
        }
    }

    #[inline(always)]
    pub fn serialize(&self, r: &mut [[u8; POLYBYTES]; K]) {
        for (poly, bytes) in self.into_iter().zip(r) {
            poly.serialize(bytes);
        }
    }
}
pub type KyberPolyVec<const K: usize> = PolyVec<KyberPoly, { KyberPoly::N }, K>;

impl<const K: usize> KyberPolyVec<K> {
    #[doc(hidden)]
    pub fn new_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut pv = Self::default();
        for i in 0..K {
            pv[i] = KyberPoly::new_random(rng);
        }
        pv
    }

    #[inline]
    pub fn getnoise_eta1(&mut self, prf: &mut Prf, seed: &[u8; NOISE_SEED_BYTES], nonce: u8) {
        if K == 2 {
            const ETA1: usize = 3;
            let mut buf = [0u8; ETA1 * KYBER_N / 4];
            for (i, poly) in self.as_mut().iter_mut().enumerate() {
                prf.absorb_prf(seed, i as u8 + nonce);
                prf.squeeze(&mut buf);
                poly.cbd3(&buf);
            }
        } else {
            self.getnoise_eta2(prf, seed, nonce);
        }
    }

    #[inline]
    pub fn getnoise_eta2(&mut self, prf: &mut Prf, seed: &[u8; NOISE_SEED_BYTES], nonce: u8) {
        const ETA2: usize = 2;
        prf.absorb_prf(seed, nonce);
        let mut buf = [0u8; ETA2 * KYBER_N / 4];
        for (i, poly) in self.as_mut().iter_mut().enumerate() {
            prf.absorb_prf(seed, i as u8 + nonce);
            prf.squeeze(&mut buf);
            poly.cbd2(&buf);
        }
    }

    #[inline] // more possibilities for code with constant d to be optimized?
    pub fn compress<const D: usize>(&self, ct: &mut [[[u8; D]; 32]; K]) {
        for (poly, a) in self.into_iter().zip(ct.iter_mut()) {
            poly.compress(a);
        }
    }

    #[inline]
    pub fn decompress<const D: usize>(&mut self, ct: &[[[u8; D]; 32]; K]) {
        for (poly, a) in self.into_iter().zip(ct.iter()) {
            poly.decompress(a);
        }
    }
}

pub type DilithiumPolyVec<const K: usize> = PolyVec<DilithiumPoly, { DilithiumPoly::N }, K>;

impl<const K: usize> DilithiumPolyVec<K> {
    pub fn new_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut pv = DilithiumPolyVec::<K>::default();
        for i in 0..K {
            pv[i] = DilithiumPoly::new_random(rng);
        }
        pv
    }
}
