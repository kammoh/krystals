use super::{keccak_f1600::Keccak1600, *};
use crate::poly::{kyber::NOISE_SEED_BYTES, UNIFORM_SEED_BYTES};

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
    const RATE_LANES: u8 = 17;
    const DELIM: u8 = 0x06;
}
pub struct Sha3_512Params;

impl KeccakParams for Sha3_512Params {
    const RATE_LANES: u8 = 9;
    const DELIM: u8 = 0x06;
}

pub struct Shake128Params;

impl KeccakParams for Shake128Params {
    const RATE_LANES: u8 = 21;
    const DELIM: u8 = 0x1f;
}
pub struct Shake256Params;

impl KeccakParams for Shake256Params {
    const RATE_LANES: u8 = 17;
    const DELIM: u8 = 0x1f;
}

pub trait HasKeccak<P: KeccakParams> {
    type Keccak: KeccakOps<P> + KeccakState;
    fn keccak(&mut self) -> &mut Self::Keccak;
}

pub trait Digest<P: KeccakParams, const DIGEST_BYTES: usize>:
    Default + Zeroize + ZeroizeOnDrop + SpongeOps<P>
{
    const DIGEST_BYTES: usize = DIGEST_BYTES;
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

impl<T> SpongeOps<Sha3_256Params> for T where T: Digest<Sha3_256Params, 32> {}
impl<T> SpongeOps<Sha3_512Params> for T where T: Digest<Sha3_512Params, 64> {}

impl SpongeOps<Shake128Params> for Shake128 {}
impl SpongeOps<Shake256Params> for Shake256 {}

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

pub trait SpongeOps<P: KeccakParams>: Default + HasKeccak<P> {
    #[inline(always)]
    fn absorb(&mut self, data: &[u8]) {
        self.keccak().absorb(data);
    }
    #[inline(always)]
    fn squeeze(&mut self, out: &mut [u8]) {
        self.keccak().squeeze(out);
    }
}

pub trait HasParams<P: KeccakParams> {
    type Params: KeccakParams;
}

impl<T, P> HasParams<P> for T
where
    T: SpongeOps<P>,
    P: KeccakParams,
{
    type Params = P;
}

pub trait OneBlockAbsorb<P: KeccakParams, const ABSORB_BYTES: usize> {
    const ABSORB_BYTES: usize = ABSORB_BYTES;
    const ABSORB_LANES: usize = ABSORB_BYTES / P::LANE_BYTES;

    fn absorb_crystal_pad(&mut self, data: &[u8; ABSORB_BYTES], pad: u64);
}

pub trait CrystalsXof<P: KeccakParams>: OneBlockAbsorb<P, UNIFORM_SEED_BYTES> {
    #[inline(always)]
    fn absorb_xof_with_nonces(&mut self, data: &[u8; UNIFORM_SEED_BYTES], n1: u8, n2: u8) {
        let pad_word = u64::from_le_bytes([n1, n2, P::DELIM, 0, 0, 0, 0, 0]);
        self.absorb_crystal_pad(data, pad_word);
    }
}

pub trait CrystalsPrf<P: KeccakParams>: OneBlockAbsorb<P, { NOISE_SEED_BYTES }> {
    #[inline(always)]
    fn absorb_prf(&mut self, data: &[u8; NOISE_SEED_BYTES], nonce: u8) {
        let pad_word = (P::DELIM as u64) << 8 | nonce as u64;
        self.absorb_crystal_pad(data, pad_word);
    }
}

impl CrystalsXof<Shake128Params> for Shake128 {}

impl CrystalsPrf<Shake256Params> for Shake256 {}

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

        for (lane, bytes) in keccak.state_mut()
            [..<Self as OneBlockAbsorb<_, ABSORB_BYTES>>::ABSORB_LANES]
            .iter_mut()
            .zip(data.as_array_chunks::<LANE_BYTES>())
        {
            *lane = u64::from_le_bytes(*bytes);
        }

        keccak.state_mut()[<Self as OneBlockAbsorb<_, ABSORB_BYTES>>::ABSORB_LANES] = pad_word;

        if keccak.1 {
            for lane in keccak.state_mut()
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

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use rand::RngCore;
    use std::*;

    #[test]
    fn sha3_256_simple() {
        let mut sha3 = Sha3_256::default();
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

                use sha3::digest::Digest;
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

                use sha3::digest::Digest;
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

        let mut xof_out = [0u8; Shake128Params::RATE_BYTES];

        for n in 0..MAX_LEN {
            let mut data = vec![0u8; n];

            rng.fill_bytes(&mut data);
            shake.absorb(&data);
            shake.squeeze(&mut xof_out);
            // let xof_out = shake.squeezed_block();

            use sha3::digest::{ExtendableOutput, Update, XofReader};
            let mut another_shake = sha3::Shake128::default();
            another_shake.update(&data);
            let mut reader = another_shake.finalize_xof();
            reader.read(&mut golden_xof_out);

            assert_eq!(&golden_xof_out, &xof_out);
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

        let mut xof_out = [0u8; Shake128Params::RATE_BYTES];

        for _ in 0..N_TESTS {
            let n1 = rand::random::<u8>();
            let n2 = rand::random::<u8>();
            rng.fill_bytes(&mut data);

            data_aug[..32].copy_from_slice(&data);
            data_aug[32] = n1;
            data_aug[33] = n2;

            shake.absorb_xof_with_nonces(&data, n1, n2);
            // let xof_out = shake.squeezed_block();
            shake.squeeze(&mut xof_out);

            assert_eq!(xof_out.len(), Shake128Params::RATE_BYTES);

            {
                use sha3::digest::{ExtendableOutput, Update, XofReader};
                let mut another_shake = sha3::Shake128::default();
                another_shake.update(&data_aug);
                let mut reader = another_shake.finalize_xof();
                reader.read(&mut golden_xof_out);
            }

            assert_eq!(&golden_xof_out, &xof_out);
        }
    }
}
