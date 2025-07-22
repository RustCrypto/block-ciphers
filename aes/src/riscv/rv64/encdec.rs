#![allow(clippy::identity_op)]
#![allow(clippy::zero_prefixed_literal)]

use crate::riscv::Block;
use crate::riscv::rv64::{Block8, RoundKey, RoundKeys};
use cipher::inout::InOut;

#[inline]
pub(super) fn encrypt1<const N: usize>(keys: &RoundKeys<N>, mut block1: InOut<'_, '_, Block>) {
    let rounds = N - 1;
    let mut state1 = utils::CipherState1::load1(block1.get_in());
    for i in 0..rounds / 2 - 1 {
        state1.enc1_two_more(keys[2 * i + 0], keys[2 * i + 1]);
    }
    state1.enc1_two_last(keys[rounds - 2], keys[rounds - 1]);
    state1.xor1(&keys[rounds]);
    state1.save1(block1.get_out());
}

#[inline]
pub(super) fn encrypt8<const N: usize>(keys: &RoundKeys<N>, mut block8: InOut<'_, '_, Block8>) {
    let rounds = N - 1;
    let mut state8 = utils::CipherState8::load8(block8.get_in());
    for i in 0..rounds / 2 - 1 {
        state8.enc8_two_more(keys[2 * i + 0], keys[2 * i + 1]);
    }
    state8.enc8_two_last(keys[rounds - 2], keys[rounds - 1]);
    state8.xor8(&keys[rounds]);
    state8.save8(block8.get_out());
}

#[inline]
pub(super) fn decrypt1<const N: usize>(keys: &RoundKeys<N>, mut block1: InOut<'_, '_, Block>) {
    let rounds = N - 1;
    let mut state1 = utils::CipherState1::load1(block1.get_in());
    state1.xor1(&keys[rounds]);
    for i in (1..rounds / 2).rev() {
        state1.dec1_two_more(keys[2 * i + 0], keys[2 * i + 1]);
    }
    state1.dec1_two_last(keys[0], keys[1]);
    state1.save1(block1.get_out());
}

#[inline]
pub(super) fn decrypt8<const N: usize>(keys: &RoundKeys<N>, mut block8: InOut<'_, '_, Block8>) {
    let rounds = N - 1;
    let mut state8 = utils::CipherState8::load8(block8.get_in());
    state8.xor8(&keys[rounds]);
    for i in (1..rounds / 2).rev() {
        state8.dec8_two_more(keys[2 * i + 0], keys[2 * i + 1]);
    }
    state8.dec8_two_last(keys[0], keys[1]);
    state8.save8(block8.get_out());
}

mod utils {
    use super::*;
    use core::arch::riscv64::*;

    pub(super) struct CipherState1 {
        data: [u64; 2],
    }

    impl CipherState1 {
        #[inline(always)]
        pub(super) fn load1(block: &Block) -> Self {
            let ptr = block.as_ptr().cast::<u64>();
            let s0 = unsafe { ptr.add(0).read_unaligned() };
            let s1 = unsafe { ptr.add(1).read_unaligned() };
            Self { data: [s0, s1] }
        }

        #[inline(always)]
        pub(super) fn save1(self, block: &mut Block) {
            let b0 = self.data[0].to_ne_bytes();
            let b1 = self.data[1].to_ne_bytes();
            block[00..08].copy_from_slice(&b0);
            block[08..16].copy_from_slice(&b1);
        }

        #[inline(always)]
        pub(super) fn xor1(&mut self, key: &RoundKey) {
            self.data[0] ^= key[0];
            self.data[1] ^= key[1];
        }

        #[inline(always)]
        pub(super) fn enc1_two_more(&mut self, k0: RoundKey, k1: RoundKey) {
            let mut n0;
            let mut n1;
            self.data[0] ^= k0[0];
            self.data[1] ^= k0[1];
            n0 = unsafe { aes64esm(self.data[0], self.data[1]) };
            n1 = unsafe { aes64esm(self.data[1], self.data[0]) };
            n0 ^= k1[0];
            n1 ^= k1[1];
            self.data[0] = unsafe { aes64esm(n0, n1) };
            self.data[1] = unsafe { aes64esm(n1, n0) };
        }

        #[inline(always)]
        pub(super) fn enc1_two_last(&mut self, k0: RoundKey, k1: RoundKey) {
            let mut n0;
            let mut n1;
            self.data[0] ^= k0[0];
            self.data[1] ^= k0[1];
            n0 = unsafe { aes64esm(self.data[0], self.data[1]) };
            n1 = unsafe { aes64esm(self.data[1], self.data[0]) };
            n0 ^= k1[0];
            n1 ^= k1[1];
            self.data[0] = unsafe { aes64es(n0, n1) };
            self.data[1] = unsafe { aes64es(n1, n0) };
        }

        #[inline(always)]
        pub(super) fn dec1_two_more(&mut self, k0: RoundKey, k1: RoundKey) {
            let mut n0;
            let mut n1;
            n0 = unsafe { aes64dsm(self.data[0], self.data[1]) };
            n1 = unsafe { aes64dsm(self.data[1], self.data[0]) };
            self.data[0] = n0 ^ k1[0];
            self.data[1] = n1 ^ k1[1];
            n0 = unsafe { aes64dsm(self.data[0], self.data[1]) };
            n1 = unsafe { aes64dsm(self.data[1], self.data[0]) };
            self.data[0] = n0 ^ k0[0];
            self.data[1] = n1 ^ k0[1];
        }

        #[inline(always)]
        pub(super) fn dec1_two_last(&mut self, k0: RoundKey, k1: RoundKey) {
            let mut n0;
            let mut n1;
            n0 = unsafe { aes64dsm(self.data[0], self.data[1]) };
            n1 = unsafe { aes64dsm(self.data[1], self.data[0]) };
            self.data[0] = n0 ^ k1[0];
            self.data[1] = n1 ^ k1[1];
            n0 = unsafe { aes64ds(self.data[0], self.data[1]) };
            n1 = unsafe { aes64ds(self.data[1], self.data[0]) };
            self.data[0] = n0 ^ k0[0];
            self.data[1] = n1 ^ k0[1];
        }
    }

    pub(super) struct CipherState8 {
        data: [CipherState1; 8],
    }

    impl CipherState8 {
        #[inline(always)]
        pub(super) fn load8(blocks: &Block8) -> Self {
            Self {
                data: [
                    CipherState1::load1(&blocks[0]),
                    CipherState1::load1(&blocks[1]),
                    CipherState1::load1(&blocks[2]),
                    CipherState1::load1(&blocks[3]),
                    CipherState1::load1(&blocks[4]),
                    CipherState1::load1(&blocks[5]),
                    CipherState1::load1(&blocks[6]),
                    CipherState1::load1(&blocks[7]),
                ],
            }
        }

        #[inline(always)]
        pub(super) fn save8(self, blocks: &mut Block8) {
            for (i, state) in self.data.into_iter().enumerate() {
                state.save1(&mut blocks[i]);
            }
        }

        #[inline(always)]
        pub(super) fn xor8(&mut self, key: &RoundKey) {
            for state in &mut self.data {
                state.xor1(key);
            }
        }

        #[inline(always)]
        pub(super) fn enc8_two_more(&mut self, k0: RoundKey, k1: RoundKey) {
            for state in &mut self.data {
                state.enc1_two_more(k0, k1);
            }
        }

        #[inline(always)]
        pub(super) fn enc8_two_last(&mut self, k0: RoundKey, k1: RoundKey) {
            for state in &mut self.data {
                state.enc1_two_last(k0, k1);
            }
        }

        #[inline(always)]
        pub(super) fn dec8_two_more(&mut self, k0: RoundKey, k1: RoundKey) {
            for state in &mut self.data {
                state.dec1_two_more(k0, k1);
            }
        }

        #[inline(always)]
        pub(super) fn dec8_two_last(&mut self, k0: RoundKey, k1: RoundKey) {
            for state in &mut self.data {
                state.dec1_two_last(k0, k1);
            }
        }
    }
}
