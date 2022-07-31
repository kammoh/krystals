use super::*;
use crate::{
    lib::{fmt::Formatter, ops::MulAssign},
    utils::i64_,
};

pub(crate) const DILITHIUM_Q: i32 = 8_380_417; // ((1<<23) - (1<<13) + 1)

pub(crate) const MONT: i32 = -4186625; // 2^32 % Q

pub(crate) const QINV: i32 = 58_728_449; // q^(-1) mod 2^32

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct DilithiumFq(pub i32);

impl Debug for DilithiumFq {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(f, "{}", self.0)
    }
}

impl AddAssign for DilithiumFq {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl SubAssign for DilithiumFq {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

impl Add for DilithiumFq {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl Sub for DilithiumFq {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}

/// For a < 2^{31} - 2^{22},
///  computes `a mod Q` in `[-6_283_009, 6_283_007]` (inclusive range)
#[inline(always)]
fn reduce32(a: i32) -> i32 {
    debug_assert!(a <= i32::MAX - (1 << 22));
    let t = (a + (1 << 22)) >> 23;
    let r = a - t.wrapping_mul(DILITHIUM_Q);
    debug_assert!(-6_283_009 <= r && r <= 6_283_008, "a={a} r={r}");
    r
}

/// for `a`: -2^{31}*Q <= a <= 2^31*Q, returns a*2^{-32} (mod Q) such that -Q < r < Q.
#[inline(always)]
const fn montgomery_reduce(a: i64) -> i32 {
    debug_assert!(-(1 << 31) * DILITHIUM_Q as i64 <= a && a <= (1 << 31) * DILITHIUM_Q as i64);
    let t = (a as i32).wrapping_mul(QINV);
    let r = i64_::high32(a - (t as i64 * DILITHIUM_Q as i64));
    debug_assert!(
        (r as i64 * MONT as i64).rem_euclid(DILITHIUM_Q as i64) == a.rem_euclid(DILITHIUM_Q as i64)
    );
    debug_assert!(-DILITHIUM_Q < r && r < DILITHIUM_Q);
    r
}

// Add Q if input coefficient is negative
#[inline(always)]
fn caddq(a: i32) -> i32 {
    a + ((a >> 31) & DILITHIUM_Q)
}

#[inline(always)]
pub const fn fqmul(a: i32, b: i32) -> i32 {
    montgomery_reduce(a as i64 * b as i64)
}

// For finite field element a, compute standard representative r = a mod^+ Q
#[inline(always)]
fn freeze(a: i32) -> i32 {
    caddq(reduce32(a))
}

impl Mul<i32> for DilithiumFq {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: i32) -> Self {
        Self(fqmul(self.0, rhs))
    }
}

impl MulAssign<i32> for DilithiumFq {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: i32) {
        *self = *self * rhs;
    }
}

impl Field for DilithiumFq {
    type E = i32;

    const Q: Self::E = DILITHIUM_Q;

    #[inline(always)]
    fn reduce(self) -> Self {
        Self(freeze(self.0))
    }

    #[inline(always)]
    fn caddq(self) -> Self {
        Self(caddq(self.0))
    }

    #[inline(always)]
    fn maybe_reduce(self) -> Self {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    const MONT_SQUARED: i32 = ((MONT as i64).pow(2) % DILITHIUM_Q as i64) as i32; // MONT^2
    const NUM_TESTS: usize = if cfg!(miri) { 100 } else { 1_000_000 };


    #[test]
    fn test_reduce() {
        let mut rng = rand::thread_rng();

        for _ in 0..NUM_TESTS {
            let x: i32 = rng.gen_range(i32::MIN..=i32::MAX - (1 << 22));
            let br = freeze(x);
            assert!(-DILITHIUM_Q <= br && br < DILITHIUM_Q);
            assert_eq!(
                (br + DILITHIUM_Q) % DILITHIUM_Q,
                x.rem_euclid(DILITHIUM_Q),
                "barrett_reduce failed for {}",
                x
            );
        }
    }

    #[test]
    fn test_fqmul() {
        let mut rng = rand::thread_rng();
        for _ in 0..NUM_TESTS {
            // let x: i32 = rng.gen_range(i32::MIN..i32::MAX);
            let x = rng.gen_range(-DILITHIUM_Q..=DILITHIUM_Q);
            let y = rng.gen_range(-DILITHIUM_Q..=DILITHIUM_Q);
            let z_mont = fqmul(x, y);
            let z = (z_mont as i64 * MONT as i64).rem_euclid(DILITHIUM_Q as i64) as i32;
            let z_bar = fqmul(z_mont, MONT_SQUARED);
            assert_eq!(z_bar.rem_euclid(DILITHIUM_Q), z);
            assert_eq!(
                z,
                (x as i64 * y as i64).rem_euclid(DILITHIUM_Q as i64) as i32,
                "fqmul failed for {:?} \n z_mont = {}, z = {}",
                (x, y),
                z_mont,
                z
            );
        }
    }
}
