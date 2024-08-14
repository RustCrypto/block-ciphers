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
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_docs, rust_2018_idioms)]
#![allow(clippy::needless_range_loop)]

pub use cipher;

use cipher::{
    consts::{U1, U16},
    AlgorithmName, Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, InOut,
    InvalidLength, KeyInit, KeySizeUser, ParBlocksSizeUser,
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

mod consts;
use consts::{PHI, ROUNDS, S, S_INVERSE};

type Words = [u32; 4];
type RoundKeys = [Words; ROUNDS + 1];

/// Serpent block cipher.
#[derive(Clone)]
pub struct Serpent {
    round_keys: RoundKeys,
}

fn get_bit(x: usize, i: usize) -> u8 {
    (x >> i) as u8 & 0x01
}

fn linear_transform_bitslice(mut words: Words) -> Words {
    words[0] = words[0].rotate_left(13);
    words[2] = words[2].rotate_left(3);
    words[1] ^= words[0] ^ words[2];
    words[3] = words[3] ^ words[2] ^ (words[0] << 3);
    words[1] = words[1].rotate_left(1);
    words[3] = words[3].rotate_left(7);
    words[0] ^= words[1] ^ words[3];
    words[2] = words[2] ^ words[3] ^ (words[1] << 7);
    words[0] = words[0].rotate_left(5);
    words[2] = words[2].rotate_left(22);
    words
}

fn linear_transform_inverse_bitslice(mut words: Words) -> Words {
    words[2] = words[2].rotate_right(22);
    words[0] = words[0].rotate_right(5);
    words[2] = words[2] ^ words[3] ^ (words[1] << 7);
    words[0] ^= words[1] ^ words[3];
    words[3] = words[3].rotate_right(7);
    words[1] = words[1].rotate_right(1);
    words[3] = words[3] ^ words[2] ^ (words[0] << 3);
    words[1] ^= words[0] ^ words[2];
    words[2] = words[2].rotate_right(3);
    words[0] = words[0].rotate_right(13);
    words
}

fn apply_s(index: usize, nibble: u8) -> u8 {
    S[index % 8][nibble as usize]
}

fn apply_s_inverse(index: usize, nibble: u8) -> u8 {
    S_INVERSE[index % 8][nibble as usize]
}

fn apply_s_bitslice(index: usize, [w1, w2, w3, w4]: Words) -> Words {
    let mut words = [0u32; 4];

    for i in 0..32 {
        let quad = apply_s(
            index,
            get_bit(w1 as usize, i)
                | get_bit(w2 as usize, i) << 1
                | get_bit(w3 as usize, i) << 2
                | get_bit(w4 as usize, i) << 3,
        );

        for l in 0..4 {
            words[l] |= u32::from(get_bit(quad as usize, l)) << i;
        }
    }

    words
}

fn apply_s_inverse_bitslice(index: usize, [w1, w2, w3, w4]: Words) -> Words {
    let mut words = [0u32; 4];
    for i in 0..32 {
        let quad = apply_s_inverse(
            index,
            get_bit(w1 as usize, i)
                | get_bit(w2 as usize, i) << 1
                | get_bit(w3 as usize, i) << 2
                | get_bit(w4 as usize, i) << 3,
        );
        for l in 0..4 {
            words[l] |= u32::from(get_bit(quad as usize, l)) << i;
        }
    }
    words
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
            for j in 0..32 {
                let input = get_bit(a as usize, j)
                    | get_bit(b as usize, j) << 1
                    | get_bit(c as usize, j) << 2
                    | get_bit(d as usize, j) << 3;
                let output = apply_s(sbox_index, input);
                for l in 0..4 {
                    k[4 * i + l] |= u32::from(get_bit(output as usize, l)) << j;
                }
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

        for i in 0..ROUNDS - 1 {
            let xb = xor(b, self.round_keys[i]);
            let s = apply_s_bitslice(i, xb);
            b = linear_transform_bitslice(s);
        }

        let xb = xor(b, self.round_keys[ROUNDS - 1]);
        let s = apply_s_bitslice(ROUNDS - 1, xb);
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
        let xb = apply_s_inverse_bitslice(ROUNDS - 1, s);
        b = xor(xb, self.round_keys[ROUNDS - 1]);

        for i in (0..ROUNDS - 1).rev() {
            let s = linear_transform_inverse_bitslice(b);
            let xb = apply_s_inverse_bitslice(i, s);
            b = xor(xb, self.round_keys[i]);
        }

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
