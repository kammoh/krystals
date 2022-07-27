use core::{fmt::Formatter, ops::MulAssign};

use super::*;

pub(crate) const KYBER_Q: i16 = 3_329;

pub(crate) const MONT: i16 = -1044; // 2^16 mod q

pub(crate) const QINV: i16 = -3327; // q^-1 mod 2^16

// pub type KyberFq = FqEl<i16, { KYBER_Q as usize }>;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct KyberFq(pub [i16; 2]);

impl Debug for KyberFq {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(f, "{}, {}", self.0[0], self.0[1])
    }
}

impl AddAssign for KyberFq {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        self.0[0] += rhs.0[0];
        self.0[1] += rhs.0[1];
    }
}

impl SubAssign for KyberFq {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        self.0[0] -= rhs.0[0];
        self.0[1] -= rhs.0[1];
    }
}

impl Add for KyberFq {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        Self([self.0[0] + rhs.0[0], self.0[1] + rhs.0[1]])
    }
}

impl Sub for KyberFq {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        Self([self.0[0] - rhs.0[0], self.0[1] - rhs.0[1]])
    }
}

impl Mul<i16> for KyberFq {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: i16) -> Self {
        Self([fqmul(self.0[0], rhs), fqmul(self.0[1], rhs)])
    }
}

impl MulAssign<i16> for KyberFq {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: i16) {
        self.0[0] = fqmul(self.0[0], rhs);
        self.0[1] = fqmul(self.0[1], rhs);
    }
}

pub(crate) fn caddq(x: i16) -> i16 {
    x + ((x >> 15) & KYBER_Q)
}

impl KyberFq {
    pub fn freeze(&self) -> Self {
        Self([caddq(self.0[0]), caddq(self.0[1])])
    }

    #[inline(always)]
    pub fn basemul(&self, other: Self, zeta: i16) -> Self {
        let (a0, a1) = (self.0[0], self.0[1]);
        let (b0, b1) = (other.0[0], other.0[1]);

        // using Karatsuba to reduce 5 fqmul operations to 4
        let z0 = fqmul(a0, b0);
        let z1 = fqmul(a1, b1);
        Self([fqmul(zeta, z1) + z0, fqmul(a1 + a0, b1 + b0) - z1 - z0])
    }

    #[inline(always)]
    pub fn basemul_acc(&self, other: Self, zeta: i16, r: &mut Self) {
        let (a0, a1) = (self.0[0], self.0[1]);
        let (b0, b1) = (other.0[0], other.0[1]);

        // using Karatsuba to reduce 5 fqmul operations to 4
        let z0 = fqmul(a0, b0);
        let z1 = fqmul(a1, b1);

        r.0[0] += fqmul(zeta, z1) + z0;
        r.0[1] += fqmul(a1 + a0, b1 + b0) - z1 - z0;
    }
}

const V: i16 = (((1 << 26) + (KYBER_Q / 2) as i32) / KYBER_Q as i32) as i16;

fn barrett_reduce(a: i16) -> i16 {
    let a = a as i32;
    let t = ((V as i32 * a + (1 << 25)) >> 26) as i16;
    let r = (a - (t as i32 * KYBER_Q as i32)) as i16;

    debug_assert!(
        -KYBER_Q / 2 <= r && r <= KYBER_Q / 2,
        "barret reduce of {} was {}",
        a,
        r
    );
    r
}

impl Field for KyberFq {
    type E = i16;

    const Q: Self::E = 3329;

    #[inline(always)]
    fn reduce(self) -> Self {
        Self([barrett_reduce(self.0[0]), barrett_reduce(self.0[1])])
    }

    #[inline(always)]
    fn caddq(self) -> Self {
        Self([caddq(self.0[0]), caddq(self.0[1])])
    }

    #[inline(always)]
    fn maybe_reduce(self) -> Self {
        // FIXME
        Self([barrett_reduce(self.0[0]), barrett_reduce(self.0[1])])
    }
}

#[inline(always)]
const fn montgomery_reduce(a: i32) -> i16 {
    let a_lo = a as i16;
    // let t = (a_lo as i32 * QINV as i32) as i16;
    let t = a_lo.wrapping_mul(QINV);
    ((a - (t as i32) * (KYBER_Q as i32)) >> 16) as i16
}

/// Multiplication followed by Montgomery reduction
/// returns  a * b * MONT^{-1} mod KYBER_Q
#[inline(always)]
pub const fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce((a as i32) * (b as i32))
}

#[cfg(test)]
mod tests {
    use super::*;
    const MONT_SQUARED: i16 = ((MONT as i32).pow(2) % KYBER_Q as i32) as i16; // MONT^2
    const NUM_TESTS: usize = if cfg!(miri) { 100 } else { 1_000_000 };

    #[test]
    fn test_barrett_reduce() {
        for _ in 0..NUM_TESTS {
            let x: i16 = rand::random();
            let br = barrett_reduce(x);
            assert!(-KYBER_Q / 2 <= br && br <= KYBER_Q / 2);
            assert_eq!(
                (br + KYBER_Q) % KYBER_Q,
                x.rem_euclid(KYBER_Q),
                "barrett_reduce failed for {}",
                x
            );
        }
    }
    #[test]
    fn test_fqmul() {
        for _ in 0..NUM_TESTS {
            let x: i16 = rand::random();
            let y = rand::random();
            let z_mont = fqmul(x, y);
            let z = (z_mont as i32 * MONT as i32).rem_euclid(KYBER_Q as i32) as i16;
            let z_bar = fqmul(z_mont, MONT_SQUARED);
            assert_eq!(z_bar.rem_euclid(KYBER_Q), z);
            assert_eq!(
                z,
                (x as i32 * y as i32).rem_euclid(KYBER_Q as i32) as i16,
                "fqmul failed for {:?} \n z_mont = {}, z = {}",
                (x, y),
                z_mont,
                z
            );
        }
    }
}
