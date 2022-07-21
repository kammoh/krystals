use crunchy::unroll;

const NLANES: usize = 25;
const NROUNDS: usize = 24;
struct Keccak1600([u64; NLANES]);

// starting from lane (0, 1)
const RHO: [u32; NLANES - 1] = {
    let mut rho = [0u32; NLANES - 1];
    let mut t = 0;
    let (mut i, mut j) = (0, 1);
    while t < NLANES - 1 {
        rho[t] = (((t + 1) * (t + 2) / 2) % 64) as u32;
        (i, j) = ((3 * i + 2 * j) % 5, i);
        t += 1;
    }
    rho
};

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

const RC: [u64; NROUNDS] = [
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

const NUM_ROUNDS: usize = 24;

impl Keccak1600 {
    #[inline(always)]
    pub(crate) fn absorb_block(&mut self, block: &[u8]) {
        debug_assert_eq!(block.len() % 8, 0);

        for (b, s) in block.chunks_exact(8).zip(self.0.iter_mut()) {
            *s ^= u64::from_le_bytes(b.try_into().unwrap()); // FIXME
        }

        self.permute::<NUM_ROUNDS>();
    }

    #[inline(always)]
    pub(crate) fn copy_bytes(&self, out: &mut [u8]) {
        for (o, s) in out.chunks_mut(8).zip(self.0.iter()) {
            o.copy_from_slice(&s.to_le_bytes()[..o.len()]);
        }
    }

    #[inline(always)]
    pub(crate) fn permute<const NUM_ROUNDS: usize>(&mut self) {
        for round in 0..NUM_ROUNDS {
            let mut array = [0u64; 5];

            // θ (theta)
            // Compute the parity of each column and xor that into two nearby columns
            // a[i][j][k] ← a[i][j][k] ⊕ parity(a[0..5][j−1][k]) ⊕ parity(a[0..5][j+1][k−1])
            unroll! {
                for j in 0..5{
                    unroll! {
                        for i in 0..5{
                            //  parity(a[..][j])
                            array[j] ^= self.0[5 * i + j];
                        }
                    }
                }
            }
            unroll! {
                for j in 0..5{
                    unroll! {
                        for i in 0..5{
                            self.0[5 * i + j] ^= array[(j + 4) % 5] ^ array[(j + 1) % 5].rotate_left(1);
                        }
                    }
                }
            }

            // π(ρ(_)) (rho + pi)
            // ρ: Bitwise rotate each of the 25 words by a different triangular number
            // π: Permute the 25 words in a fixed pattern
            let mut last = self.0[1];
            unroll! {
                for x in 0..23 {
                    (last, self.0[PI[x]]) = (self.0[PI[x]], last.rotate_left(RHO[x]));
                }
            }
            self.0[1] = last.rotate_left(RHO[23]);

            // χ (chi)
            // Bitwise combine along rows
            // a[i][j] ← a[i][j] ⊕ (¬a[i][j+1] & a[i][j+2])
            for y in 0..5 {
                unroll! {
                    for x in 0..5 {
                        array[x] = !self.0[5 * y + (x + 1) % 5] & self.0[5 * y + (x + 2) % 5];
                    }
                }
                unroll! {
                    for x in 0..5 {
                        self.0[5 * y + x] ^= array[x];
                    }
                }
            }

            // ι (iota: only the first lane)
            self.0[0] ^= RC[round];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak_f1600() {
        // Test vectors are from XKCP
        // https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-1600-IntermediateValues.txt

        let mut state = Keccak1600([
            0xF1258F7940E1DDE7,
            0x84D5CCF933C0478A,
            0xD598261EA65AA9EE,
            0xBD1547306F80494D,
            0x8B284E056253D057,
            0xFF97A42D7F8E6FD4,
            0x90FEE5A0A44647C4,
            0x8C5BDA0CD6192E76,
            0xAD30A6F71B19059C,
            0x30935AB7D08FFC64,
            0xEB5AA93F2317D635,
            0xA9A6E6260D712103,
            0x81A57C16DBCF555F,
            0x43B831CD0347C826,
            0x01F22F1A11A5569F,
            0x05E5635A21D9AE61,
            0x64BEFEF28CC970F2,
            0x613670957BC46611,
            0xB87C5A554FD00ECB,
            0x8C3EE88A1CCF32C8,
            0x940C7922AE3A2614,
            0x1841F924A2C509E4,
            0x16F53526E70465C2,
            0x75F644E97F30A13B,
            0xEAF1FF7B5CECA249,
        ]);
        let next_state = Keccak1600([
            0x2D5C954DF96ECB3C,
            0x6A332CD07057B56D,
            0x093D8D1270D76B6C,
            0x8A20D9B25569D094,
            0x4F9C4F99E5E7F156,
            0xF957B9A2DA65FB38,
            0x85773DAE1275AF0D,
            0xFAF4F247C3D810F7,
            0x1F1B9EE6F79A8759,
            0xE4FECC0FEE98B425,
            0x68CE61B6B9CE68A1,
            0xDEEA66C4BA8F974F,
            0x33C43D836EAFB1F5,
            0xE00654042719DBD9,
            0x7CF8A9F009831265,
            0xFD5449A6BF174743,
            0x97DDAD33D8994B40,
            0x48EAD5FC5D0BE774,
            0xE3B8C8EE55B7B03C,
            0x91A0226E649E42E9,
            0x900E3129E7BADD7B,
            0x202A9EC5FAA3CCE8,
            0x5B3402464E1C3DB6,
            0x609F4E62A44C1059,
            0x20D06CD26A8FBF5C,
        ]);

        state.permute::<NUM_ROUNDS>();

        assert_eq!(state.0, next_state.0);
    }
}
