pub mod fips202;
pub mod keccak_f1600;

use core::ops::{BitXorAssign, Index, IndexMut, Range, RangeTo};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::utils::split::Splitter;

#[derive(Zeroize)]
pub struct Keccak<T: Default + Copy + Zeroize, const NL: usize>(pub [T; NL], pub bool);

impl<T: Default + Copy + Zeroize, const NL: usize> Default for Keccak<T, NL> {
    #[inline]
    fn default() -> Self {
        Self([T::default(); NL], false)
    }
}

pub trait KeccakParams {
    const LANE_BYTES: usize = 8;
    const RATE_LANES: u8;
    const RATE_BYTES: usize = Self::RATE_LANES as usize * Self::LANE_BYTES;
    const DELIM: u8;
    const NUM_ROUNDS: usize = 24;
}

pub trait KeccakOps<P: KeccakParams>: Zeroize {
    type Params: KeccakParams;
    const LANE_BYTES: usize = P::LANE_BYTES;

    const RC: [u64; 24] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808a,
        0x8000000080008000,
        0x000000000000808b,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008a,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000a,
        0x000000008000808b,
        0x800000000000008b,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800a,
        0x800000008000000a,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ];

    fn absorb(&mut self, data: &[u8]);
    fn finalize_xor(&mut self);
    fn squeeze(&mut self, out: &mut [u8]);

    fn permute(&mut self) {
        for rc in Self::RC[..{ P::NUM_ROUNDS }].iter() {
            self.theta();
            self.rho_pi();
            self.chi();
            self.iota(rc);
        }
    }

    fn theta(&mut self);
    fn rho_pi(&mut self);
    fn chi(&mut self);
    fn iota(&mut self, rc: &u64);
}

pub trait KeccakState: Zeroize {
    type Lane: BitXorAssign<Self::Lane> + Copy;

    type State: Index<usize, Output = Self::Lane>
        + IndexMut<usize, Output = Self::Lane>
        + Index<Range<usize>, Output = [Self::Lane]>
        + IndexMut<Range<usize>, Output = [Self::Lane]>
        + Index<RangeTo<usize>, Output = [Self::Lane]>
        + IndexMut<RangeTo<usize>, Output = [Self::Lane]>
        + AsRef<[Self::Lane]>
        + AsMut<[Self::Lane]>;

    const NUM_LANES: usize;

    fn state(&mut self) -> &mut [Self::Lane];

    #[inline(always)]
    fn reset(&mut self) {
        self.zeroize();
    }
}
