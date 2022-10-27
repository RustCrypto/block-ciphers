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

// TODO: remove dependency on byteorder
use byteorder::{ByteOrder, LE};
use cipher::{consts::U16, AlgorithmName, BlockCipher, InvalidLength, KeyInit, KeySizeUser};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

mod consts;
use consts::{PHI, ROUNDS, S, S_INVERSE};

type Key = [u8; 16];
type Subkeys = [Key; ROUNDS + 1];
type Block128 = [u8; 16];
type Word = [u8; 16];

/// Serpent block cipher.
#[derive(Clone)]
pub struct Serpent {
    k: Subkeys,
}

fn get_bit(x: usize, i: usize) -> u8 {
    (x >> i) as u8 & 0x01
}

fn linear_transform_bitslice(input: Block128, output: &mut Block128) {
    let mut words = [0u32; 4];
    LE::read_u32_into(&input, &mut words);

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

    LE::write_u32_into(&words, output);
}

fn linear_transform_inverse_bitslice(input: Block128, output: &mut Block128) {
    let mut words = [0u32; 4];
    LE::read_u32_into(&input, &mut words);

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

    LE::write_u32_into(&words, output);
}

fn round_bitslice(i: usize, b_i: Block128, k: Subkeys, b_output: &mut Block128) {
    let xored_block = xor_block(b_i, k[i]);

    let s_i = apply_s_bitslice(i, xored_block);

    if i == ROUNDS - 1 {
        *b_output = xor_block(s_i, k[ROUNDS]);
    } else {
        linear_transform_bitslice(s_i, b_output);
    }
}

#[allow(clippy::useless_let_if_seq)]
fn round_inverse_bitslice(i: usize, b_i_next: Block128, k: Subkeys, b_output: &mut Block128) {
    let mut s_i = [0u8; 16];

    if i == ROUNDS - 1 {
        s_i = xor_block(b_i_next, k[ROUNDS]);
    } else {
        linear_transform_inverse_bitslice(b_i_next, &mut s_i);
    }

    let xored = apply_s_inverse_bitslice(i, s_i);

    *b_output = xor_block(xored, k[i]);
}

fn apply_s(index: usize, nibble: u8) -> u8 {
    S[index % 8][nibble as usize]
}

fn apply_s_inverse(index: usize, nibble: u8) -> u8 {
    S_INVERSE[index % 8][nibble as usize]
}

fn apply_s_bitslice(index: usize, word: Word) -> Word {
    let mut output = [0u8; 16];

    let w1 = LE::read_u32(&word[0..4]);
    let w2 = LE::read_u32(&word[4..8]);
    let w3 = LE::read_u32(&word[8..12]);
    let w4 = LE::read_u32(&word[12..16]);

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

    LE::write_u32_into(&words, &mut output);

    output
}

fn apply_s_inverse_bitslice(index: usize, word: Word) -> Word {
    let mut output = [0u8; 16];
    let w1 = LE::read_u32(&word[0..4]);
    let w2 = LE::read_u32(&word[4..8]);
    let w3 = LE::read_u32(&word[8..12]);
    let w4 = LE::read_u32(&word[12..16]);
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
    LE::write_u32_into(&words, &mut output);
    output
}

fn xor_block(b1: Block128, k: Key) -> Block128 {
    let mut xored: Block128 = [0u8; 16];
    for (i, _) in b1.iter().enumerate() {
        xored[i] = b1[i] ^ k[i];
    }
    xored
}

fn expand_key(source: &[u8], len_bits: usize, key: &mut [u8; 32]) {
    key[..source.len()].copy_from_slice(source);
    if len_bits < 256 {
        let byte_i = len_bits / 8;
        let bit_i = len_bits % 8;
        key[byte_i] |= 1 << bit_i;
    }
}

impl Serpent {
    #[allow(clippy::many_single_char_names)]
    fn key_schedule(key: [u8; 32]) -> Subkeys {
        let mut words = [0u32; 140];

        LE::read_u32_into(&key, &mut words[..8]);

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
            let a = words[(4 * i) as usize];
            let b = words[(4 * i + 1) as usize];
            let c = words[(4 * i + 2) as usize];
            let d = words[(4 * i + 3) as usize];
            // calculate keys in bitslicing mode
            for j in 0..32 {
                let input = get_bit(a as usize, j)
                    | get_bit(b as usize, j) << 1
                    | get_bit(c as usize, j) << 2
                    | get_bit(d as usize, j) << 3;
                let output = apply_s(sbox_index, input as u8);
                for l in 0..4 {
                    k[(4 * i + l) as usize] |= u32::from(get_bit(output as usize, l)) << j;
                }
            }
        }

        let mut sub_keys: Subkeys = [[0u8; 16]; ROUNDS + 1];
        for i in 0..r {
            LE::write_u32(&mut sub_keys[i][..4], k[4 * i]);
            LE::write_u32(&mut sub_keys[i][4..8], k[4 * i + 1]);
            LE::write_u32(&mut sub_keys[i][8..12], k[4 * i + 2]);
            LE::write_u32(&mut sub_keys[i][12..], k[4 * i + 3]);
        }

        sub_keys
    }
}

impl BlockCipher for Serpent {}

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
        let mut k = [0u8; 32];
        expand_key(key, key.len() * 8, &mut k);
        Ok(Serpent {
            k: Serpent::key_schedule(k),
        })
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

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl Drop for Serpent {
    fn drop(&mut self) {
        self.k.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl ZeroizeOnDrop for Serpent {}

cipher::impl_simple_block_encdec!(
    Serpent, U16, cipher, block,
    encrypt: {
        let mut b = block.clone_in().into();
        for i in 0..ROUNDS {
            round_bitslice(i, b, cipher.k, &mut b);
        }
        *block.get_out() = b.into();
    }
    decrypt: {
        let mut b = block.clone_in().into();
        for i in (0..ROUNDS).rev() {
            round_inverse_bitslice(i, b, cipher.k, &mut b);
        }
        *block.get_out() = b.into();
    }
);
