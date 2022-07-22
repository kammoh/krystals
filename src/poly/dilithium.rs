use crate::field::{
    dilithium::{fqmul, DilithiumFq, DILITHIUM_Q, MONT},
    Field,
};

use super::{Poly, Polynomial};

pub(crate) const DILITHIUM_N: usize = 256;

const ROOT_OF_UNITY: i32 = 1753; // 2Nth (512-th) root of 1 mod Q

pub type DilithiumPoly = Poly<DilithiumFq, DILITHIUM_N>;

const ZETAS: [i32; DILITHIUM_N - 1] = {
    let mut zetas = [0i32; DilithiumPoly::N - 1];
    let mut i = 1;
    const ROOT_OF_UNITY_MONT: i32 =
        ((MONT as i64 * ROOT_OF_UNITY as i64) % DILITHIUM_Q as i64) as i32;
    let mut omega = MONT;
    while i < DilithiumPoly::N {
        let br = (i as u8).reverse_bits() as usize;
        omega = fqmul(omega % DILITHIUM_Q, ROOT_OF_UNITY_MONT); //((omega as i32 * ROOT_OF_UNITY as i32) % KYBER_Q as i32) as i16;
        zetas[br - 1] = omega;
        i += 1;
    }
    zetas
};

impl Polynomial<DILITHIUM_N> for DilithiumPoly {
    type F = DilithiumFq;

    const INV_NTT_SCALE: <Self::F as Field>::E = 41_978;

    #[inline(always)]
    fn zetas(k: usize) -> <Self::F as Field>::E {
        ZETAS[k]
    }

    fn pointwise(&self, other: &Self, result: &mut Self) {
        for ((a, b), c) in self
            .as_ref()
            .iter()
            .zip(other.as_ref().iter())
            .zip(result.as_mut().iter_mut())
        {
            c.0 = fqmul(a.0, b.0);
        }
        // Unrolled version is significantly slower! (using chunks_exact is even slower, ~ 100% slower!)
        // const UNROLL: usize = 2;
        // for ((a, b), c) in self
        //     .as_ref()
        //     .into_array_ref_iter::<UNROLL>()
        //     .zip(other.as_ref().into_array_ref_iter::<UNROLL>())
        //     .zip(result.as_mut().into_array_mut_iter::<UNROLL>())
        // {
        //     c[0].0 = fqmul(a[0].0, b[0].0);
        //     c[1].0 = fqmul(a[1].0, b[1].0);
        // }
    }
}

// #[cfg(test)]
use rand::{CryptoRng, Rng, RngCore};

// #[cfg(test)]
impl DilithiumPoly {
    pub fn new_random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut poly = Self::default();
        for i in 0..Self::N {
            poly[i].0 = rng.gen_range(-DILITHIUM_Q / 2..=DILITHIUM_Q / 2);
        }
        poly
    }

    pub fn into_array(&self) -> [<<Self as Polynomial<{ Self::N }>>::F as Field>::E; Self::N] {
        // array_init::array_init(|i: usize| self[i].0)
        self.0.map(|x| x.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntt_and_then_invtt() {
        let mut rng = rand::thread_rng();
        for testcase in 0..3_000 {
            let mut poly = DilithiumPoly::new_random(&mut rng);
            let poly_copy = poly.clone();
            poly.ntt();
            poly.reduce();
            poly.inv_ntt();

            for f in poly.as_mut() {
                *f = *f * 1; // * R^-1
            }

            assert_eq!(poly, poly_copy, "failed testcase #{}", testcase);
        }
    }

    // #[test]
    // fn test_ntt_and_then_invtt_ref() {
    //     for testcase in 1..1000 {
    //         let mut poly = Poly::new_random();
    //         let poly_copy = poly.clone();
    //         crystals_cref::ntt(&mut poly.0);
    //         crystals_cref::invntt(&mut poly.0);
    //         assert_eq!(poly, poly_copy, "failed testcase #{}", testcase);
    //     }
    // }

    #[test]
    fn test_ntt_vs_ref() {
        let mut rng = rand::thread_rng();
        for _ in 0..3_000 {
            let mut poly = DilithiumPoly::new_random(&mut rng);
            // println!("poly before ntt: {:?}", poly);
            let mut p = poly.into_array();
            poly.ntt();
            // poly.reduce();
            // println!("poly after ntt: {:?}", poly);
            // println!("p before ntt: {:?}", p);
            crystals_cref::dilithium::ntt(&mut p);

            for i in 0..DilithiumPoly::N {
                assert_eq!(p[i], poly[i].0);
            }
            // assert_eq!(poly., poly_copy, "failed testcase #{}", testcase);
        }
    }

    #[test]
    fn test_invntt_vs_ref() {
        let mut rng = rand::thread_rng();
        for _ in 0..3_000 {
            let mut poly = DilithiumPoly::new_random(&mut rng);
            // println!("poly before ntt: {:?}", poly);
            let mut p = [0i32; DilithiumPoly::N];
            for i in 0..DilithiumPoly::N {
                p[i] = poly[i].0;
            }
            poly.inv_ntt();
            crystals_cref::dilithium::inv_ntt(&mut p);

            for i in 0..DilithiumPoly::N {
                assert_eq!(p[i], poly[i].0);
            }
        }
    }
}
