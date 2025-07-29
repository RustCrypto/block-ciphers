use ::cipher::{Array, consts::U8};

use super::*;
use core::arch::riscv64::*;

pub(super) struct AlignedBlock {
    data: [u64; 2],
}

impl AlignedBlock {
    #[inline(always)]
    pub(super) fn load(block: &Block) -> Self {
        let (chunks, tail) = block.as_chunks();
        assert!(tail.is_empty());
        let data = core::array::from_fn(|i| u64::from_ne_bytes(chunks[i]));
        Self { data }
    }

    #[inline(always)]
    pub(super) fn save(self, block: &mut Block) {
        let b0 = self.data[0].to_ne_bytes();
        let b1 = self.data[1].to_ne_bytes();
        block[..8].copy_from_slice(&b0);
        block[8..].copy_from_slice(&b1);
    }

    #[inline(always)]
    pub(super) fn xor(&mut self, key: &RoundKey) {
        self.data[0] ^= key[0];
        self.data[1] ^= key[1];
    }

    #[inline]
    #[target_feature(enable = "zkne")]
    pub(super) fn encrypt(&mut self, pair: &[RoundKey; 2]) {
        let mut n0;
        let mut n1;
        self.data[0] ^= pair[0][0];
        self.data[1] ^= pair[0][1];
        n0 = aes64esm(self.data[0], self.data[1]);
        n1 = aes64esm(self.data[1], self.data[0]);
        n0 ^= pair[1][0];
        n1 ^= pair[1][1];
        self.data[0] = aes64esm(n0, n1);
        self.data[1] = aes64esm(n1, n0);
    }

    #[inline]
    #[target_feature(enable = "zkne")]
    pub(super) fn encrypt_last(&mut self, pair: &[RoundKey; 2]) {
        let mut n0;
        let mut n1;
        self.data[0] ^= pair[0][0];
        self.data[1] ^= pair[0][1];
        n0 = aes64esm(self.data[0], self.data[1]);
        n1 = aes64esm(self.data[1], self.data[0]);
        n0 ^= pair[1][0];
        n1 ^= pair[1][1];
        self.data[0] = aes64es(n0, n1);
        self.data[1] = aes64es(n1, n0);
    }

    #[inline]
    #[target_feature(enable = "zknd")]
    pub(super) fn decrypt(&mut self, pair: &[RoundKey; 2]) {
        let mut n0;
        let mut n1;
        n0 = aes64dsm(self.data[0], self.data[1]);
        n1 = aes64dsm(self.data[1], self.data[0]);
        self.data[0] = n0 ^ pair[1][0];
        self.data[1] = n1 ^ pair[1][1];
        n0 = aes64dsm(self.data[0], self.data[1]);
        n1 = aes64dsm(self.data[1], self.data[0]);
        self.data[0] = n0 ^ pair[0][0];
        self.data[1] = n1 ^ pair[0][1];
    }

    #[inline]
    #[target_feature(enable = "zknd")]
    pub(super) fn decrypt_last(&mut self, pair: &[RoundKey; 2]) {
        let mut n0;
        let mut n1;
        n0 = aes64dsm(self.data[0], self.data[1]);
        n1 = aes64dsm(self.data[1], self.data[0]);
        self.data[0] = n0 ^ pair[1][0];
        self.data[1] = n1 ^ pair[1][1];
        n0 = aes64ds(self.data[0], self.data[1]);
        n1 = aes64ds(self.data[1], self.data[0]);
        self.data[0] = n0 ^ pair[0][0];
        self.data[1] = n1 ^ pair[0][1];
    }
}

pub(super) struct AlignedParBlock {
    data: Array<AlignedBlock, U8>,
}

impl AlignedParBlock {
    #[inline(always)]
    pub(super) fn load(blocks: &Block8) -> Self {
        let data = blocks.map(|b| AlignedBlock::load(&b));
        Self { data }
    }

    #[inline(always)]
    pub(super) fn save(self, blocks: &mut Block8) {
        for (i, state) in self.data.into_iter().enumerate() {
            state.save(&mut blocks[i]);
        }
    }

    #[inline(always)]
    pub(super) fn xor(&mut self, key: &RoundKey) {
        for state in &mut self.data {
            state.xor(key);
        }
    }

    #[inline]
    #[target_feature(enable = "zkne")]
    pub(super) fn encrypt(&mut self, pair: &[RoundKey; 2]) {
        for state in &mut self.data {
            state.encrypt(pair);
        }
    }

    #[inline]
    #[target_feature(enable = "zkne")]
    pub(super) fn encrypt_last(&mut self, pair: &[RoundKey; 2]) {
        for state in &mut self.data {
            state.encrypt_last(pair);
        }
    }

    #[inline]
    #[target_feature(enable = "zknd")]
    pub(super) fn decrypt(&mut self, pair: &[RoundKey; 2]) {
        for state in &mut self.data {
            state.decrypt(pair);
        }
    }

    #[inline]
    #[target_feature(enable = "zknd")]
    pub(super) fn decrypt_last(&mut self, pair: &[RoundKey; 2]) {
        for state in &mut self.data {
            state.decrypt_last(pair);
        }
    }
}
