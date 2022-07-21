use core::fmt::Debug;
use core::ops::{Add, AddAssign, Div, Mul, MulAssign, Rem, Sub, SubAssign};
use rand::distributions::uniform::SampleUniform;

pub mod dilithium;
pub mod kyber;

pub trait Zero: Sized + PartialEq + Add<Self, Output = Self> {
    const ZERO: Self;

    #[inline(always)]
    fn zero() -> Self {
        Self::ZERO
    }

    #[inline(always)]
    fn set_zero(&mut self) {
        *self = Self::ZERO;
    }

    #[inline(always)]
    fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }
}

pub trait One: Sized + PartialEq + Mul<Self, Output = Self> {
    const ONE: Self;

    #[inline(always)]
    fn one() -> Self {
        Self::ONE
    }

    #[inline(always)]
    fn set_one(&mut self) {
        *self = Self::ONE;
    }

    #[inline(always)]
    fn is_one(&self) -> bool {
        *self == Self::ONE
    }
}

macro_rules! zero_one_impl {
    ($t:ty) => {
        impl Zero for $t {
            const ZERO: Self = 0;
        }
        impl One for $t {
            const ONE: Self = 1;
        }
    };
}

zero_one_impl!(usize);
zero_one_impl!(u8);
zero_one_impl!(u16);
zero_one_impl!(u32);
zero_one_impl!(u64);
#[cfg(has_i128)]
zero_one_impl!(u128);

zero_one_impl!(isize);
zero_one_impl!(i8);
zero_one_impl!(i16);
zero_one_impl!(i32);
zero_one_impl!(i64);
#[cfg(has_i128)]
zero_one_impl!(i128);

///
///

pub trait NumLike:
    Clone
    + Copy
    + PartialEq
    + Debug
    + Default
    + PartialOrd
    + Ord
    + SampleUniform
    + Zero
    + One
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + Mul<Self, Output = Self>
    + Div<Self, Output = Self>
    + Rem<Self, Output = Self>
    + SubAssign<Self>
    + AddAssign<Self>
{
}

impl<
        T: Clone
            + Copy
            + PartialEq
            + Debug
            + Default
            + PartialOrd
            + Ord
            + SampleUniform
            + Zero
            + One
            + Add<Self, Output = Self>
            + Sub<Self, Output = Self>
            + Mul<Self, Output = Self>
            + Div<Self, Output = Self>
            + Rem<Self, Output = Self>
            + SubAssign<Self>
            + AddAssign<Self>,
    > NumLike for T
{
}

pub trait Field:
    Sized
    + Copy
    + Default
    + Debug
    + Mul<Self::E, Output = Self>
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + AddAssign<Self>
    + SubAssign<Self>
    + MulAssign<Self::E>
{
    type E: NumLike;

    const Q: Self::E;

    fn reduce(self) -> Self;
    fn caddq(self) -> Self;

    fn maybe_reduce(self) -> Self;
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FqEl<E, const Q: usize>(pub E)
where
    E: NumLike;

// impl<E, const Q: usize> Mul for FqEl<E, Q>
// where
//     E: NumLike,
// {
//     type Output = Self;
//     fn mul(self, rhs: Self) -> Self {
//         FqEl(self.0 * rhs.0)
//     }
// }

impl<E, const Q: usize> MulAssign for FqEl<E, Q>
where
    E: NumLike,
    FqEl<E, Q>: Mul<Output = Self>,
{
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl<E: NumLike, const Q: usize> From<E> for FqEl<E, Q> {
    fn from(e: E) -> Self {
        Self(e)
    }
}

macro_rules! into_num_impl {
    ($t:ty) => {
        impl<const Q: usize> From<FqEl<$t, Q>> for $t {
            fn from(val: FqEl<$t, Q>) -> Self {
                val.0
            }
        }
    };
}

into_num_impl!(usize);
into_num_impl!(u8);
into_num_impl!(u16);
into_num_impl!(u32);
into_num_impl!(u64);
#[cfg(has_i128)]
into_num_impl!(u128);

into_num_impl!(isize);
into_num_impl!(i8);
into_num_impl!(i16);
into_num_impl!(i32);
into_num_impl!(i64);
#[cfg(has_i128)]
into_num_impl!(i128);

impl<E, const Q: usize> Add for FqEl<E, Q>
where
    E: NumLike,
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl<E, const Q: usize> Sub for FqEl<E, Q>
where
    E: NumLike,
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl<E, const Q: usize> AddAssign<Self> for FqEl<E, Q>
where
    E: NumLike,
{
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl<E, const Q: usize> SubAssign<Self> for FqEl<E, Q>
where
    E: NumLike,
{
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}
