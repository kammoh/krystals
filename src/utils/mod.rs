#![allow(dead_code)]

pub(crate) mod unsafe_utils;
pub(crate) use unsafe_utils::*;

use crate::field::NumLike;


pub(crate) const fn ceil_div<const X: usize>(n: usize) -> usize {
    (n + (X - 1)) / X
}

// return next multiple of x after n, such that result % x == 0 , and result >= n
pub(crate) const fn next_multiple_of<const X: usize>(n: usize) -> usize {
    ceil_div::<X>(n) * X
}

// extended euclidean algorithm
pub(crate) fn egcd<T: NumLike + Copy>(a: T, b: T) -> (T, T, T) {
    let (mut old_r, mut r) = (a, b);
    let (mut old_s, mut s) = (T::one(), T::zero());

    while r != T::zero() {
        let (quotient, remainder) = (old_r / r, old_r % r);
        (old_r, r) = (r, remainder);
        (old_s, s) = (s, old_s - quotient * s);
    }
    // returns (x, y, gcd) where a*x + b*y = gcd
    (old_s, (old_r - old_s * a) / b, old_r)
}

pub(crate) fn invm<T: NumLike + Copy>(a: T, m: T) -> Option<T> {
    match egcd(a, m) {
        (x, _, gcd) if gcd == T::one() => Some(x),
        _ => None,
    }
}

// pub(crate) trait ModQ<S>: Copy {
//     const Q: S;
//     fn mod_q(&self) -> S;
//     fn multm(&self, other: Self) -> S;
//     fn addm(&self, other: Self) -> S;
//     fn subm(&self, other: Self) -> S;
//     fn invm(&self) -> Option<S>;
// }

// #[cfg(test)]
// // only used in testing
// impl<T: Num + PartialEq + Euclid + AsPrimitive<i16> + AsPrimitive<i128> + FromPrimitive> ModQ<i16>
//     for T
// {
//     const Q: i16 = KYBER_Q;

//     fn mod_q(&self) -> i16 {
//         self.rem_euclid(&T::from_i16(KYBER_Q).unwrap()).as_()
//     }

//     fn multm(&self, other: Self) -> i16 {
//         (self.mod_q() as i32 * other.mod_q() as i32).mod_q()
//     }

//     fn addm(&self, other: Self) -> i16 {
//         (self.mod_q() as i32 + other.mod_q() as i32).mod_q()
//     }

//     fn subm(&self, other: Self) -> i16 {
//         (self.mod_q() as i32 - other.mod_q() as i32).mod_q()
//     }

//     fn invm(&self) -> Option<i16> {
//         invm(self.mod_q(), Self::Q)
//     }
// }
