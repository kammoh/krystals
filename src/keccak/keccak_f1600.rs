use super::{Keccak, KeccakOps, KeccakParams, KeccakState};
use crate::lib::slice::{Iter, IterMut};
use crate::utils::split::Splitter;

use array_init::array_init;
use crunchy::unroll;
use zeroize::Zeroize;

pub type Keccak1600 = Keccak<u64, 25>;

// starting from lane (0, 1)
const RHO: [u32; 24] = {
    let mut rho = [0u32; 24];
    let mut t = 0;
    let (mut i, mut j) = (0, 1);
    while t < rho.len() {
        rho[t] = (((t + 1) * (t + 2) / 2) % 64) as u32;
        (i, j) = ((3 * i + 2 * j) % 5, i);
        t += 1;
    }
    rho
};

const PI: [u8; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

impl KeccakState for Keccak1600 {
    const NUM_LANES: usize = 25;

    type Lane = u64;
    type State = [Self::Lane; 25];

    #[inline(always)]
    fn state(&self) -> &[Self::Lane; Self::NUM_LANES] {
        &self.0
    }

    #[inline(always)]
    fn state_mut(&mut self) -> &mut [Self::Lane; Self::NUM_LANES] {
        &mut self.0
    }

    #[inline(always)]
    fn reset(&mut self) {
        if self.1 {
            self.zeroize();
        }
        self.1 = true;
    }

    #[inline(always)]
    fn lanes_iter_mut<P: KeccakParams>(&mut self) -> IterMut<'_, Self::Lane> {
        self.0[..{ P::RATE_LANES as usize }].iter_mut()
    }
    #[inline(always)]
    fn lanes_iter<P: KeccakParams>(&self) -> Iter<'_, Self::Lane> {
        self.0[..{ P::RATE_LANES as usize }].iter()
    }
}

impl<T, P: KeccakParams> KeccakOps<P> for T
where
    T: KeccakState<Lane = u64>,
{
    type Params = P;

    #[inline(always)]
    fn finalize_xor(&mut self) {
        const LANE_BYTES: usize = 8;
        assert!(LANE_BYTES == P::LANE_BYTES);
        const FINALIZE_CONST: u64 = 1 << (LANE_BYTES * 8 - 1); // 1 << 63
        self.state_mut()[P::RATE_LANES as usize - 1] ^= FINALIZE_CONST;
    }

    fn absorb(&mut self, mut data: &[u8]) {
        const LANE_BYTES: usize = 8;
        assert!(LANE_BYTES == P::LANE_BYTES);
        assert!(P::RATE_LANES as usize <= Self::NUM_LANES);

        self.reset();

        let mut data_chunk;

        loop {
            for lane in self.lanes_iter_mut::<P>() {
                (data_chunk, data) = data.try_split_array_ref::<LANE_BYTES>();
                match data_chunk {
                    Some(chunk) => *lane ^= u64::from_le_bytes(*chunk),
                    None => {
                        // the loops always end here
                        let mut buf = [0u8; LANE_BYTES];
                        let rem_len = data.len();
                        buf[..rem_len].copy_from_slice(data);
                        buf[rem_len] = P::DELIM;
                        *lane ^= u64::from_le_bytes(buf);
                        KeccakOps::<P>::finalize_xor(self);
                        return;
                    }
                };
            }
            KeccakOps::<P>::permute(self);
        }
        // unreachable!();
    }

    fn squeeze(&mut self, out: &mut [u8]) {
        for out_blocks in out.chunks_mut(P::RATE_BYTES) {
            KeccakOps::<P>::permute(self);
            for (lane, out_bytes) in self.lanes_iter::<P>().zip(out_blocks.chunks_mut(8)) {
                out_bytes.copy_from_slice(&lane.to_le_bytes());
            }
        }
    }

    /// θ (theta): Compute the parity of each column and xor that into two nearby columns
    /// a[i][j][k] ← a[i][j][k] ⊕ parity(a[0..5][j−1][k]) ⊕ parity(a[0..5][j+1][k−1])
    #[inline(always)]
    fn theta(&mut self) {
        let state = self.state_mut();
        let mut parity: [u64; 5] = array_init(|i| state[i]);

        unroll! {
            for j in 0..5{
                unroll! {
                    // due to a BUG in `crunchy::unroll!` macro which starts from 0 without the `.step_by()`
                    // TODO: use our own unroll macro
                    for i in (1..5).step_by(1){
                        //  parity(a[..][j])
                        parity[j] ^= state[5 * i + j];
                    }
                }
            }
        }
        unroll! {
            for j in 0..5{
                unroll! {
                    for i in 0..5{
                        state[5 * i + j] ^= parity[(j + 4) % 5] ^ parity[(j + 1) % 5].rotate_left(1);
                    }
                }
            }
        }
    }

    /// rho then pi, i.e., π(ρ(_))
    /// ρ: Bitwise rotate each of the 25 words by a different triangular number
    /// π: Permute the 25 words in a fixed pattern
    #[inline(always)]
    fn rho_pi(&mut self) {
        #![allow(unused_assignments)]
        let state = self.state_mut();
        let mut last = state[PI[23] as usize];
        unroll! {
            for i in 0..24 {
                let pi = PI[i] as usize;
                (last, state[pi]) = (state[pi], last.rotate_left(RHO[i]));
            }
        }
    }

    /// χ (chi): Bitwise combine along rows
    /// a[i][j] ← a[i][j] ⊕ (¬a[i][j+1] & a[i][j+2])
    #[inline(always)]
    fn chi(&mut self) {
        // for plane in self.0.into_array_chunks_mut::<5>() {

        for plane in self.state_mut().as_mut().chunks_exact_mut(5) {
            let mut tmp = [0; 2];
            unroll! {
                // due to an unroll! bug
                for j in (3..5).step_by(1) {
                    tmp[j - 3] = !plane[(j + 1) % 5] & plane[(j + 2) % 5];
                }
            }
            unroll! {
                for j in (0..3).step_by(1) {
                    plane[j] ^= !plane[(j + 1) % 5] & plane[(j + 2) % 5];
                }
            }
            unroll! {
                for j in (3..5).step_by(1) {
                    plane[j] ^= tmp[j - 3];
                }
            }
        }
    }

    /// ι (iota): the first lane is XORed with the round constant
    #[inline(always)]
    fn iota(&mut self, rc: &u64) {
        self.state_mut()[0] ^= rc;
    }
}
