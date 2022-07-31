#![allow(dead_code)]

use crate::lib::{mem::size_of, ops::Shl};

pub(crate) mod unsafe_utils;

pub(crate) use unsafe_utils::*;

use crate::field::NumLike;

pub trait LowHigh<HT: Sized>: Sized + Shl<usize, Output = Self> {
    type HT;
    const HT_BITS: u8 = size_of::<HT>() as u8 * 8;

    fn low(self) -> Self::HT;
    fn high(self) -> Self::HT;
}

pub(crate) mod u64_ {
    use crate::utils::size_of;

    type T = u64;
    type HT = u32;
    const HT_BITS: u8 = size_of::<HT>() as u8 * 8;

    pub const fn low32(x: T) -> HT {
        x as _
    }
    pub const fn high32(x: T) -> HT {
        (x >> HT_BITS) as _
    }
}

pub(crate) mod i64_ {
    use crate::utils::size_of;

    type T = i64;
    type HT = i32;
    const HT_BITS: u8 = size_of::<HT>() as u8 * 8;

    #[inline(always)]
    pub const fn high32(x: T) -> HT {
        (x >> HT_BITS) as _
    }
}

impl LowHigh<u32> for u64 {
    type HT = u32;
    #[inline(always)]
    fn low(self) -> Self::HT {
        self as _
    }

    #[inline(always)]
    fn high(self) -> Self::HT {
        (self >> Self::HT_BITS) as _
    }
}

impl LowHigh<i32> for i64 {
    type HT = i32;
    #[inline(always)]
    fn low(self) -> Self::HT {
        self as _
    }
    #[inline(always)]
    fn high(self) -> Self::HT {
        (self >> Self::HT_BITS) as _
    }
}

impl LowHigh<u16> for u32 {
    type HT = u16;
    #[inline(always)]
    fn low(self) -> Self::HT {
        self as _
    }
    #[inline(always)]
    fn high(self) -> Self::HT {
        (self >> Self::HT_BITS) as _
    }
}

impl LowHigh<u8> for u16 {
    type HT = u8;
    #[inline(always)]
    fn low(self) -> Self::HT {
        self as _
    }
    #[inline(always)]
    fn high(self) -> Self::HT {
        (self >> Self::HT_BITS) as _
    }
}

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
    let (mut old_s, mut s) = (T::ONE, T::ZERO);

    while r != T::ZERO {
        let (quotient, remainder) = (old_r / r, old_r % r);
        (old_r, r) = (r, remainder);
        (old_s, s) = (s, old_s - quotient * s);
    }
    // returns (x, y, gcd) where a*x + b*y = gcd
    (old_s, (old_r - old_s * a) / b, old_r)
}

macro_rules! impl_egcd {
    ($($t:ty),+) => {
        $(
            paste::paste! {
                pub(crate) const fn [< egcd _ $t >] (a: $t, b: $t) -> ($t, $t, $t) {
                    let (mut old_r, mut r) = (a, b);
                    let (mut old_s, mut s) = (0, 0);

                    while r != 0 {
                        let (quotient, remainder) = (old_r / r, old_r % r);
                        (old_r, r) = (r, remainder);
                        (old_s, s) = (s, old_s - quotient * s);
                    }
                    // returns (x, y, gcd) where a*x + b*y = gcd
                    (old_s, (old_r - old_s * a) / b, old_r)
                }
                pub(crate) const fn [< gcd _ $t >] (a: $t, m: $t) -> $t {
                    let (_, _, gcd) = [< egcd _ $t >](a, m);
                    gcd
                }
            }
        )+
    };
}

impl_egcd!(u8, u16, u64);

pub(crate) fn invm<T: NumLike + Copy>(a: T, m: T) -> Option<T> {
    match egcd(a, m) {
        (x, _, gcd) if gcd == T::ONE => Some(x),
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
