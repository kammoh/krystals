use core::{
    borrow::{Borrow, BorrowMut},
    ops::{BitXorAssign, Index, IndexMut, Range, RangeTo},
};

use crunchy::unroll;
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

pub trait KeccakParams {
    const LANE_BYTES: usize;
    const RATE_LANES: u8;
    const RATE_BYTES: usize = Self::RATE_LANES as usize * Self::LANE_BYTES;
    const DELIM: u8;
    const NUM_ROUNDS: usize = 24;
}

pub trait KeccakOps<P: KeccakParams>: Zeroize {
    type Params: KeccakParams;
    const LANE_BYTES: usize = P::LANE_BYTES;

    fn absorb(&mut self, data: &[u8]);
    fn finalize_xor(&mut self);
    fn squeeze(&mut self, out: &mut [u8]);

    fn permute(&mut self) {
        for rc in RC[..{ P::NUM_ROUNDS }].iter() {
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

impl KeccakState for Keccak1600 {
    const NUM_LANES: usize = 25;

    type Lane = u64;
    type State = [Self::Lane; 25];

    #[inline(always)]
    fn state(&mut self) -> &mut [Self::Lane] {
        &mut self.0
    }

    #[inline(always)]
    fn reset(&mut self) {
        if self.1 {
            self.zeroize();
        }
        self.1 = true;
    }
}

impl<'a, T, P: KeccakParams> KeccakOps<P> for T
where
    T: KeccakState<Lane = u64>,
{
    type Params = P;

    #[inline(always)]
    fn finalize_xor(&mut self) {
        const LANE_BYTES: usize = 8;
        assert!(LANE_BYTES == P::LANE_BYTES);
        const FINALIZE_CONST: u64 = 1 << (LANE_BYTES * 8 - 1); // 1 << 63
        self.state()[P::RATE_LANES as usize - 1] ^= FINALIZE_CONST;
    }

    fn absorb(&mut self, mut data: &[u8]) {
        const LANE_BYTES: usize = 8;
        assert!(LANE_BYTES == P::LANE_BYTES);
        assert!(P::RATE_LANES as usize <= Self::NUM_LANES);

        self.reset();

        let mut data_chunk;

        loop {
            let state = &mut self.state()[..{ P::RATE_LANES as usize }];
            for lane in state.iter_mut() {
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
        // let mut out_chunks = out.into_array_chunks_mut::<8>();// slower! :/

        let mut out_chunks = out.chunks_exact_mut(8);
        loop {
            KeccakOps::<P>::permute(self);
            let state = self.state();
            for lane in state[..{ P::RATE_LANES as usize }].iter() {
                match out_chunks.next() {
                    Some(chunk) => chunk.copy_from_slice(&lane.to_le_bytes()),
                    _ => {
                        let rem = out_chunks.into_remainder();
                        rem.copy_from_slice(&lane.to_le_bytes()[..rem.len()]);
                        return;
                    }
                };
            }
        }
    }

    // not any faster than squeeze() :/
    // #[inline]
    // pub(crate) fn squeeze_n<const N: usize>(&mut self, out: &mut [u8; N]) {
    //     self.permute();
    //     for (lane, out_block) in self.0[..N / LANE_BYTES]
    //         .iter()
    //         .zip(out.chunks_exact_mut(LANE_BYTES))
    //     {
    //         out_block.copy_from_slice(&lane.to_le_bytes());
    //     }
    // }

    /// θ (theta): Compute the parity of each column and xor that into two nearby columns
    /// a[i][j][k] ← a[i][j][k] ⊕ parity(a[0..5][j−1][k]) ⊕ parity(a[0..5][j+1][k−1])
    #[inline(always)]
    fn theta(&mut self) {
        let state = self.state();
        let mut parity: [u64; 5] = array_init::array_init(|i| state[i]);

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
        let state = self.state();
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

        for plane in self.state().as_mut().chunks_exact_mut(5) {
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
        self.state()[0] ^= rc;
    }
}

pub mod fips202 {

    use super::*;
    pub const NUM_ROUNDS: usize = 24;

    #[derive(Default, Zeroize, ZeroizeOnDrop)]
    pub struct Sha3_256(Keccak1600);

    #[derive(Default, Zeroize, ZeroizeOnDrop)]
    pub struct Sha3_512(Keccak1600);

    #[derive(Default, Zeroize, ZeroizeOnDrop)]
    pub struct Shake128(Keccak1600);

    #[derive(Default, Zeroize, ZeroizeOnDrop)]
    pub struct Shake256(Keccak1600);

    pub struct Sha3_256Params;

    impl KeccakParams for Sha3_256Params {
        const LANE_BYTES: usize = 8;
        const RATE_LANES: u8 = 17;
        const DELIM: u8 = 0x06;
    }
    pub struct Sha3_512Params;

    impl KeccakParams for Sha3_512Params {
        const LANE_BYTES: usize = 8;
        const RATE_LANES: u8 = 9;
        const DELIM: u8 = 0x06;
    }

    pub struct Shake128Params;

    impl KeccakParams for Shake128Params {
        const LANE_BYTES: usize = 8;
        const RATE_LANES: u8 = 21;
        const DELIM: u8 = 0x1f;
    }
    pub struct Shake256Params;

    impl KeccakParams for Shake256Params {
        const LANE_BYTES: usize = 8;
        const RATE_LANES: u8 = 17;
        const DELIM: u8 = 0x1f;
    }

    pub trait HasKeccak<P: KeccakParams> {
        type Keccak: KeccakOps<P> + KeccakState;
        fn keccak(&mut self) -> &mut Self::Keccak;
    }

    pub trait Digest<P: KeccakParams, const DIGEST_BYTES: usize>:
        Default + Zeroize + ZeroizeOnDrop + Sha3Ops<P>
    {
        const RATE_LANES: u8 = P::RATE_LANES;
        const DELIM: u8 = P::DELIM;

        // fn digest(&mut self, data: &[u8], out: &mut [u8; DIGEST_BYTES]);
        #[inline(always)]
        fn digest(&mut self, data: &[u8], out: &mut [u8; DIGEST_BYTES]) {
            self.absorb(data);
            self.squeeze(out);
        }
    }

    impl Digest<Sha3_256Params, 32> for Sha3_256 {}
    impl Digest<Sha3_512Params, 64> for Sha3_512 {}

    impl<T> Sha3Ops<Sha3_256Params> for T where T: Digest<Sha3_256Params, 32> {}
    impl<T> Sha3Ops<Sha3_512Params> for T where T: Digest<Sha3_512Params, 64> {}

    impl HasKeccak<Sha3_256Params> for Sha3_256 {
        type Keccak = Keccak1600;
        #[inline(always)]
        fn keccak(&mut self) -> &mut Self::Keccak {
            &mut self.0
        }
    }

    impl HasKeccak<Sha3_512Params> for Sha3_512 {
        type Keccak = Keccak1600;
        #[inline(always)]
        fn keccak(&mut self) -> &mut Self::Keccak {
            &mut self.0
        }
    }

    impl HasKeccak<Shake128Params> for Shake128 {
        type Keccak = Keccak1600;
        #[inline(always)]
        fn keccak(&mut self) -> &mut Self::Keccak {
            &mut self.0
        }
    }

    impl HasKeccak<Shake256Params> for Shake256 {
        type Keccak = Keccak1600;
        #[inline(always)]
        fn keccak(&mut self) -> &mut Self::Keccak {
            &mut self.0
        }
    }

    pub trait Sha3Ops<P: KeccakParams>: Default + HasKeccak<P> {
        #[inline(always)]
        fn absorb(&mut self, data: &[u8]) {
            self.keccak().absorb(data);
        }
        #[inline(always)]
        fn squeeze(&mut self, out: &mut [u8]) {
            self.keccak().squeeze(out);
        }
    }

    pub trait Xof<P: KeccakParams>: Sha3Ops<P> {}

    impl<T> Sha3Ops<Shake128Params> for T where T: Xof<Shake128Params> {}
    impl<T> Sha3Ops<Shake256Params> for T where T: Xof<Shake256Params> {}

    pub trait SqueezeOneBlock<P: KeccakParams>: HasKeccak<P> + Sha3Ops<P> {
        type OutputBlock: Sized;
        // fn squeezed_block(&mut self) -> &Self::OutputBlock;
        #[inline]
        fn squeezed_block(&mut self) -> &Self::OutputBlock {
            #![allow(unsafe_code)] // FIXME FIXME FIXME SAFETY
            let keccak = self.keccak();
            keccak.permute();

            let a = unsafe { keccak.state().get_unchecked(..P::RATE_LANES as usize) };
            unsafe { &*(a.as_ptr() as *const Self::OutputBlock) }
        }
    }

    pub trait OneBlockAbsorb<P: KeccakParams, const ABSORB_BYTES: usize> {
        const ABSORB_BYTES: usize = ABSORB_BYTES;
        const ABSORB_LANES: usize = ABSORB_BYTES / P::LANE_BYTES;

        fn absorb_crystal_pad(&mut self, data: &[u8; ABSORB_BYTES], pad: u64);
    }

    pub trait CrystalsXof<P: KeccakParams>: OneBlockAbsorb<P, 32> {
        #[inline(always)]
        fn absorb_xof_with_nonces(&mut self, data: &[u8; 32], n1: u8, n2: u8) {
            let pad_word = u64::from_le_bytes([n1, n2, P::DELIM, 0, 0, 0, 0, 0]);
            self.absorb_crystal_pad(data, pad_word);
        }
    }

    impl Xof<Shake128Params> for Shake128 {}
    impl SqueezeOneBlock<Shake128Params> for Shake128 {
        type OutputBlock = [u8; Shake128Params::RATE_BYTES];
    }

    impl CrystalsXof<Shake128Params> for Shake128 {}

    impl<T, P, const ABSORB_BYTES: usize> OneBlockAbsorb<P, ABSORB_BYTES> for T
    where
        P: KeccakParams,
        T: HasKeccak<P, Keccak = Keccak1600>, // FIXME
    {
        fn absorb_crystal_pad(&mut self, data: &[u8; ABSORB_BYTES], pad_word: u64) {
            const LANE_BYTES: usize = 8;

            assert!(LANE_BYTES == P::LANE_BYTES);
            assert!(ABSORB_BYTES < P::RATE_BYTES);
            assert!(ABSORB_BYTES % P::LANE_BYTES == 0);

            let keccak = self.keccak();

            for (lane, bytes) in keccak.state()
                [..<Self as OneBlockAbsorb<_, ABSORB_BYTES>>::ABSORB_LANES]
                .iter_mut()
                .zip(data.into_array_chunks_iter::<LANE_BYTES>())
            {
                *lane = u64::from_le_bytes(*bytes);
            }

            keccak.state()[<Self as OneBlockAbsorb<_, ABSORB_BYTES>>::ABSORB_LANES] = pad_word;

            if keccak.1 {
                for lane in keccak.state()
                    [<Self as OneBlockAbsorb<_, ABSORB_BYTES>>::ABSORB_LANES + 1..]
                    .iter_mut()
                {
                    *lane = 0;
                }
            }
            keccak.1 = true;

            KeccakOps::<P>::finalize_xor(keccak);
        }
    }

    impl Xof<Shake256Params> for Shake256 {}
}

#[cfg(test)]
mod tests {
    use rand::RngCore;

    use super::{fips202::*, *};

    #[test]
    fn sha3_256_simple() {
        let mut sha3 = fips202::Sha3_256::default();
        let mut digest = [0; 32];

        sha3.digest(&[], &mut digest);

        assert_eq!(
            &digest,
            b"\
                \xa7\xff\xc6\xf8\xbf\x1e\xd7\x66\x51\xc1\x47\x56\xa0\x61\xd6\x62\
                \xf5\x80\xff\x4d\xe4\x3b\x49\xfa\x82\xd8\x0a\x4b\x80\xf8\x43\x4a\
            "
        );

        sha3.digest(b"hello", &mut digest);

        assert_eq!(
            &digest,
            b"\
                \x33\x38\xbe\x69\x4f\x50\xc5\xf3\x38\x81\x49\x86\xcd\xf0\x68\x64\
                \x53\xa8\x88\xb8\x4f\x42\x4d\x79\x2a\xf4\xb9\x20\x23\x98\xf3\x92\
            "
        );
    }

    #[test]
    fn sha3_256_rand() {
        let mut another_sha3 = sha3::Sha3_256::default();
        let mut sha3 = fips202::Sha3_256::default();
        let mut digest = [0; 32];
        let mut rng = rand::thread_rng();

        const MAX_LEN: usize = if cfg!(miri) { 10 } else { 300 };

        for n in 0..=MAX_LEN {
            let mut data = vec![0u8; n];

            for _ in 0..=n / 8 {
                rng.fill_bytes(&mut data);

                sha3.digest(&data, &mut digest);

                use digest::Digest;
                another_sha3.update(&data);
                let golden_digest = another_sha3.finalize_reset();
                assert_eq!(golden_digest.as_slice(), &digest[..]);
            }
        }
    }

    #[test]
    fn sha3_512_rand() {
        let mut another_sha3 = sha3::Sha3_512::default();
        let mut sha3 = fips202::Sha3_512::default();
        let mut digest = [0; 64];
        let mut rng = rand::thread_rng();

        const MAX_LEN: usize = if cfg!(miri) { 10 } else { 300 };

        for n in 0..=MAX_LEN {
            let mut data = vec![0u8; n];

            for _ in 0..=n / 8 {
                rng.fill_bytes(&mut data);

                sha3.digest(&data, &mut digest);

                use digest::Digest;
                another_sha3.update(&data);
                let golden_digest = another_sha3.finalize_reset();
                assert_eq!(golden_digest.as_slice(), &digest[..]);
            }
        }
    }

    #[test]
    fn sha3_512() {
        let mut sha3 = fips202::Sha3_512::default();
        let mut digest = [0; 64];

        let input = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

        sha3.digest(input, &mut digest);

        assert_eq!(
            &digest,
            b"\
                \xf3\x2a\x94\x23\x55\x13\x51\xdf\x0a\x07\xc0\xb8\xc2\x0e\xb9\x72\
                \x36\x7c\x39\x8d\x61\x06\x60\x38\xe1\x69\x86\x44\x8e\xbf\xbc\x3d\
                \x15\xed\xe0\xed\x36\x93\xe3\x90\x5e\x9a\x8c\x60\x1d\x9d\x00\x2a\
                \x06\x85\x3b\x97\x97\xef\x9a\xb1\x0c\xbd\xe1\x00\x9c\x7d\x0f\x09\
            "
        );
    }

    #[test]
    fn shake128() {
        let mut shake = fips202::Shake128::default();
        let mut golden_xof_out = [0u8; Shake128Params::RATE_BYTES];
        let mut rng = rand::thread_rng();

        const MAX_LEN: usize = if cfg!(miri) { 6 } else { 666 };

        for n in 0..MAX_LEN {
            let mut data = vec![0u8; n];

            rng.fill_bytes(&mut data);
            shake.absorb(&data);
            let xof_out = shake.squeezed_block();

            use digest::{ExtendableOutput, Update, XofReader};
            let mut another_shake = sha3::Shake128::default();
            another_shake.update(&data);
            let mut reader = another_shake.finalize_xof();
            reader.read(&mut golden_xof_out);

            assert_eq!(&golden_xof_out, xof_out);
        }
    }

    #[test]
    fn shake128_absorb_crystals() {
        let mut shake = Shake128::default();
        let mut golden_xof_out = [0u8; Shake128Params::RATE_BYTES];
        let mut rng = rand::thread_rng();

        const N_TESTS: usize = if cfg!(miri) { 6 } else { 666 };

        let mut data = [0u8; 32];
        let mut data_aug = [0u8; 32 + 2];

        for _ in 0..N_TESTS {
            let n1 = rand::random::<u8>();
            let n2 = rand::random::<u8>();
            rng.fill_bytes(&mut data);

            data_aug[..32].copy_from_slice(&data);
            data_aug[32] = n1;
            data_aug[33] = n2;

            shake.absorb_xof_with_nonces(&data, n1, n2);
            let xof_out = shake.squeezed_block();

            assert_eq!(xof_out.len(), Shake128Params::RATE_BYTES);

            {
                use digest::{ExtendableOutput, Update, XofReader};
                let mut another_shake = sha3::Shake128::default();
                another_shake.update(&data_aug);
                let mut reader = another_shake.finalize_xof();
                reader.read(&mut golden_xof_out);
            }

            assert_eq!(&golden_xof_out, xof_out);
        }
    }
}
