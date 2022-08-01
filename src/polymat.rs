use crate::lib::ops::{Index, IndexMut};
use crate::{
    poly::kyber::KyberPoly,
    poly::{SizedPolynomial, UNIFORM_SEED_BYTES},
    polyvec::*,
};

#[derive(Debug)]
pub struct PolyMat<P, const N: usize, const K: usize, const L: usize>([PolyVec<P, N, L>; K])
where
    P: SizedPolynomial<N>;

impl<P, const N: usize, const K: usize, const L: usize> Default for PolyMat<P, N, K, L>
where
    P: SizedPolynomial<N>,
{
    #[inline]
    fn default() -> Self {
        Self([PolyVec::default(); K])
    }
}

impl<P, const N: usize, const K: usize, const L: usize> Index<usize> for PolyMat<P, N, K, L>
where
    P: SizedPolynomial<N>,
{
    type Output = PolyVec<P, N, L>;

    #[inline(always)]
    fn index(&self, i: usize) -> &Self::Output {
        &self.0[i]
    }
}

impl<P, const N: usize, const K: usize, const L: usize> IndexMut<usize> for PolyMat<P, N, K, L>
where
    P: SizedPolynomial<N>,
{
    #[inline(always)]
    fn index_mut(&mut self, i: usize) -> &mut Self::Output {
        &mut self.0[i]
    }
}

impl<P, const N: usize, const K: usize, const L: usize> AsRef<[PolyVec<P, N, L>; K]>
    for PolyMat<P, N, K, L>
where
    P: SizedPolynomial<N>,
{
    #[inline(always)]
    fn as_ref(&self) -> &[PolyVec<P, N, L>; K] {
        &self.0
    }
}

impl<P, const N: usize, const K: usize, const L: usize> AsMut<[PolyVec<P, N, L>; K]>
    for PolyMat<P, N, K, L>
where
    P: SizedPolynomial<N>,
{
    #[inline(always)]
    fn as_mut(&mut self) -> &mut [PolyVec<P, N, L>; K] {
        &mut self.0
    }
}

impl<P, const N: usize, const K: usize, const L: usize> PolyMat<P, N, K, L>
where
    P: SizedPolynomial<N>,
{
    //     #[inline]
    //     pub fn mult_vec(&self, polyvec: &PolyVec<T, N, K>) -> PolyVec<T, N, K> {
    //         let mut r = PolyVec::default();

    //         for i in 0..K {
    //             self[i].basemul_acc(&polyvec, &mut r[i]);
    //         }
    //         r
    //     }

    /// Expand seed to A matrix (or A^T if TRANSPOSED is true)
    /// For Kyber:
    ///
    /// For dilithium:
    ///                polyvec_matrix_expand TRANSPOSED = false
    #[inline(always)]
    pub fn gen_matrix<const TRANSPOSED: bool>(seed: &[u8; UNIFORM_SEED_BYTES]) -> Self {
        let mut a = Self::default();
        a.gen_matrix_into::<TRANSPOSED>(seed);
        a
    }

    #[inline(always)]
    pub fn gen_a(seed: &[u8; UNIFORM_SEED_BYTES]) -> Self {
        Self::gen_matrix::<false>(seed)
    }

    #[inline(always)]
    pub fn gen_at(seed: &[u8; UNIFORM_SEED_BYTES]) -> Self {
        Self::gen_matrix::<true>(seed)
    }

    #[inline]
    pub fn gen_matrix_into<const TRANSPOSED: bool>(&mut self, seed: &[u8; UNIFORM_SEED_BYTES]) {
        for (i, vec) in self.as_mut().iter_mut().enumerate() {
            vec.uniform_xof::<TRANSPOSED>(seed, i as u8);
        }
    }
}

pub type KyberMatrix<const K: usize> = PolyMat<KyberPoly, { KyberPoly::N }, K, K>;

#[cfg(test)]
mod tests {
    use rand::Rng;

    use crate::poly::kyber::KYBER_N;

    use super::*;

    #[test]
    fn gen_matrix() {
        gen_matrix_x::<2, true>();
        gen_matrix_x::<3, true>();
        gen_matrix_x::<4, true>();
        gen_matrix_x::<2, false>();
        gen_matrix_x::<3, false>();
        gen_matrix_x::<4, false>();
    }

    fn gen_matrix_x<const K: usize, const TRANSPOSED: bool>() {
        let mut seed = [0u8; 32];
        let mut rng = rand::thread_rng();

        const NUM_TESTS: usize = if cfg!(miri) { 3 } else { 111 };

        let mut a_ref = [[[0i16; KYBER_N]; K]; K];

        for _ in 0..NUM_TESTS {
            rng.fill(&mut seed);

            let a = KyberMatrix::<K>::gen_matrix::<TRANSPOSED>(&seed);

            crystals_cref::kyber::gen_matrix(&mut a_ref, &seed, TRANSPOSED);

            for i in 0..K {
                for j in 0..K {
                    for k in 0..KYBER_N {
                        assert_eq!(
                            a[i][j][k / 2].0[k % 2],
                            a_ref[i][j][k],
                            "i={}, j={}, k={}",
                            i,
                            j,
                            k
                        );
                    }
                }
            }
        }
    }
}
