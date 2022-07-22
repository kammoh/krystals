use crate::{poly::Polynomial, polyvec::*};

#[derive(Clone)]
pub struct PolyMat<P, const N: usize, const K: usize>
where
    P: Polynomial<N>,
{
    pub vec: [PolyVec<P, N, K>; K],
}

impl<P, const N: usize, const K: usize> Default for PolyMat<P, N, K>
where
    P: Polynomial<N>,
{
    fn default() -> Self {
        Self {
            vec: [PolyVec::default(); K],
        }
    }
}

// impl<T: Field, const N: usize, const K: usize> Mul<PolyVec<T, N, K>> for PolyMat<T, N, K> {
//     type Output = PolyVec<T, N, K>;

//     fn mul(self, rhs: PolyVec<T, N, K>) -> Self::Output {
//         self.mult_vec(&rhs)
//     }
// }

// impl<T: Field, const N: usize, const K: usize> Index<usize> for PolyMat<T, N, K> {
//     type Output = PolyVec<T, N, K>;
//     fn index<'a>(&'a self, i: usize) -> &'a Self::Output {
//         &self[i]
//     }
// }

// impl<T: Field, const N: usize, const K: usize> IndexMut<usize> for PolyMat<T, N, K> {
//     fn index_mut<'a>(&'a mut self, i: usize) -> &'a mut Self::Output {
//         &mut self[i]
//     }
// }

// impl<T: Field, const N: usize, const K: usize> PolyMat<T, N, K> {
//     #[inline]
//     pub fn mult_vec(&self, polyvec: &PolyVec<T, N, K>) -> PolyVec<T, N, K> {
//         let mut r = PolyVec::default();

//         for i in 0..K {
//             self[i].basemul_acc(&polyvec, &mut r[i]);
//         }
//         r
//     }
// }

// pub(crate) fn gen_matrix<const K: usize>(
//     seed: &[u8; KYBER_SYMBYTES],
//     transposed: bool,
// ) -> PolyMat<KyberFq, KYBER_N, K> {
//     let mut res = PolyMat::default();
//     // let mut xof = Xof::new();

//     // const XOF_BLOCKBYTES: usize = Xof::RATE_BYTES;

//     // // assert!(XOF_BLOCKBYTES == 168);

//     // // technically not the same as ref implementation but equivalent
//     // // TODO: what is the difference? why is this correct?

//     // // this is number of XOF output rate blocks needed for 1 Poly
//     // const GEN_MATRIX_NBLOCKS: usize =
//     //     ceil_div::<XOF_BLOCKBYTES>(12 * KYBER_N / 8 * (1 << 12) / KYBER_Q as usize);
//     // const BYTES_PER_POLY: usize = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES;

//     // let mut buf = [0u8; next_multiple_of::<3>(BYTES_PER_POLY)];

//     // for i in 0..K {
//     //     for j in 0..K {
//     //         if transposed {
//     //             xof.absorb(seed, i as u8, j as u8);
//     //         } else {
//     //             xof.absorb(seed, j as u8, i as u8);
//     //         }

//     //     }
//     // }
//     res
// }
