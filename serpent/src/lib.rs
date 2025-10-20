//! Pure Rust implementation of the [Serpent] block cipher.
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate implements only the low-level block cipher function, and is intended
//! for use for implementing higher-level constructions *only*. It is NOT
//! intended for direct use in applications.
//!
//! USE AT YOUR OWN RISK!
//!
//! [Serpent]: https://en.wikipedia.org/wiki/Serpent_(cipher)

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]
#![allow(clippy::needless_range_loop)]

pub use cipher;

use cipher::{
    AlgorithmName, Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, InOut,
    InvalidLength, KeyInit, KeySizeUser, ParBlocksSizeUser,
    consts::{U1, U16},
};
use core::fmt;

mod bitslice;
#[macro_use]
mod unroll;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

const PHI: u32 = 0x9e37_79b9;
const ROUNDS: usize = 32;

type Words = [u32; 4];
type RoundKeys = [Words; ROUNDS + 1];

/// Serpent block cipher.
#[derive(Clone)]
pub struct Serpent {
    round_keys: RoundKeys,
}

#[inline(always)]
fn xor(b1: Words, k: Words) -> Words {
    let mut res = [0u32; 4];
    for (i, _) in b1.iter().enumerate() {
        res[i] = b1[i] ^ k[i];
    }
    res
}

fn expand_key(source: &[u8], len_bits: usize) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..source.len()].copy_from_slice(source);
    if len_bits < 256 {
        let byte_i = len_bits / 8;
        let bit_i = len_bits % 8;
        key[byte_i] |= 1 << bit_i;
    }
    key
}

impl KeySizeUser for Serpent {
    type KeySize = U16;
}

impl KeyInit for Serpent {
    fn new(key: &cipher::Key<Self>) -> Self {
        Self::new_from_slice(key).unwrap()
    }

    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        if key.len() < 16 || key.len() > 32 {
            return Err(InvalidLength);
        }
        let key = expand_key(key, key.len() * 8);

        let mut words = [0u32; 140];

        for (src, dst) in key.chunks_exact(4).zip(words[..8].iter_mut()) {
            *dst = u32::from_le_bytes(src.try_into().unwrap());
        }

        for i in 0..132 {
            let slot = i + 8;
            words[slot] = (words[slot - 8]
                ^ words[slot - 5]
                ^ words[slot - 3]
                ^ words[slot - 1]
                ^ PHI
                ^ i as u32)
                .rotate_left(11);
        }

        let r = ROUNDS + 1;
        let words = &words[8..];
        let mut k = [0u32; 132];
        for i in 0..r {
            let sbox_index = (ROUNDS + 3 - i) % ROUNDS;
            let [a, b, c, d]: [u32; 4] = words[4 * i..][..4].try_into().unwrap();
            // calculate keys in bitslicing mode
            let output = bitslice::apply_s(sbox_index, [a, b, c, d]);
            for l in 0..4 {
                k[4 * i + l] = output[l];
            }
        }

        let mut round_keys: RoundKeys = [[0; 4]; ROUNDS + 1];
        for (src, dst) in k.chunks_exact(4).zip(round_keys.iter_mut()) {
            dst.copy_from_slice(src);
        }

        Ok(Serpent { round_keys })
    }
}

impl BlockSizeUser for Serpent {
    type BlockSize = U16;
}

impl ParBlocksSizeUser for Serpent {
    type ParBlocksSize = U1;
}

impl BlockCipherEncrypt for Serpent {
    #[inline]
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl BlockCipherEncBackend for Serpent {
    #[inline]
    fn encrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut b: [u32; 4] = read_words(block.get_in().into());

        unroll31!(i, {
            let xb = xor(b, self.round_keys[i]);
            let s = bitslice::apply_s(i, xb);
            b = bitslice::linear_transform(s);
        });

        let xb = xor(b, self.round_keys[ROUNDS - 1]);
        let s = bitslice::apply_s(ROUNDS - 1, xb);
        b = xor(s, self.round_keys[ROUNDS]);

        write_words(&b, block.get_out().into());
    }
}

impl BlockCipherDecrypt for Serpent {
    #[inline]
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl BlockCipherDecBackend for Serpent {
    #[inline]
    fn decrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut b: [u32; 4] = read_words(block.get_in().into());

        let s = xor(b, self.round_keys[ROUNDS]);
        let xb = bitslice::apply_s_inv(ROUNDS - 1, s);
        b = xor(xb, self.round_keys[ROUNDS - 1]);

        unroll31!(i, {
            let i = 30 - i;
            let s = bitslice::linear_transform_inv(b);
            let xb = bitslice::apply_s_inv(i, s);
            b = xor(xb, self.round_keys[i]);
        });

        write_words(&b, block.get_out().into());
    }
}

impl fmt::Debug for Serpent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Serpent { ... }")
    }
}

impl AlgorithmName for Serpent {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Serpent")
    }
}

impl Drop for Serpent {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        self.round_keys.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for Serpent {}

fn read_words(src: &[u8; 16]) -> Words {
    let mut res = [0; 4];
    for (src, dst) in src.chunks_exact(4).zip(res.iter_mut()) {
        *dst = u32::from_le_bytes(src.try_into().unwrap());
    }
    res
}

fn write_words(src: &Words, dst: &mut [u8; 16]) {
    for (src, dst) in src.iter().zip(dst.chunks_exact_mut(4)) {
        dst.copy_from_slice(&src.to_le_bytes());
    }
}
