//! An implementation of the [Serpent1][1] block cipher.
//! Inspired by [Serpent reference implementation][2] and [Lars Viklund Rust implementation][3].
//! [1]: https://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf
//! [2]: https://www.cl.cam.ac.uk/~fms27/serpent/
//! [3]: https://github.com/efb9-860a-e752-0dac/serpent
// #![no_std]
pub extern crate block_cipher_trait;
extern crate byteorder;
#[macro_use]
extern crate opaque_debug;

use block_cipher_trait::generic_array::typenum::{U1, U16};
use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::BlockCipher;
use block_cipher_trait::InvalidKeyLength;
use byteorder::{ByteOrder, LE};

mod consts;
use consts::{PHI, ROUNDS, S, S_INVERSE};

type Key = [u8; 16];
type Subkeys = [Key; ROUNDS + 1];
type Block128 = [u8; 16];
type Word = [u8; 16];

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

fn round_bitslice(
    i: usize,
    b_i: Block128,
    k: Subkeys,
    b_output: &mut Block128,
) {
    let xored_block = xor_block(b_i, k[i]);

    let s_i = apply_s_bitslice(i, xored_block);

    if i == ROUNDS - 1 {
        *b_output = xor_block(s_i, k[ROUNDS]);
    } else {
        linear_transform_bitslice(s_i, b_output);
    }
}
fn round_inverse_bitslice(
    i: usize,
    b_i_next: Block128,
    k: Subkeys,
    b_output: &mut Block128,
) {
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
    key[..source.len()].copy_from_slice(&source);
    if len_bits < 256 {
        let byte_i = len_bits / 8;
        let bit_i = len_bits % 8;
        key[byte_i] |= 1 << bit_i;
    }
}

impl Serpent {
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
            let a = words[(4 * i + 0) as usize];
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
                    k[(4 * i + l) as usize] |=
                        u32::from(get_bit(output as usize, l)) << j;
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

impl BlockCipher for Serpent {
    type KeySize = U16;
    type BlockSize = U16;
    type ParBlocks = U1;
    fn new(key: &GenericArray<u8, U16>) -> Self {
        Self::new_varkey(key).unwrap()
    }

    fn new_varkey(key: &[u8]) -> Result<Self, InvalidKeyLength> {
        if key.len() < 16 || key.len() > 32 {
            return Err(InvalidKeyLength);
        }
        let mut k = [0u8; 32];
        expand_key(key, key.len() * 8, &mut k);
        Ok(Serpent {
            k: Serpent::key_schedule(k),
        })
    }

    fn encrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
        let mut b = [0u8; 16];

        for (i, v) in block.iter().enumerate() {
            b[i] = *v;
        }

        for i in 0..ROUNDS {
            round_bitslice(i, b, self.k, &mut b);
        }
        *block = *GenericArray::from_slice(&b);
    }

    fn decrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
        let mut b = [0u8; 16];

        for (i, v) in block.iter().enumerate() {
            b[i] = *v;
        }

        for i in (0..ROUNDS).rev() {
            round_inverse_bitslice(i, b, self.k, &mut b);
        }

        *block = *GenericArray::from_slice(&b);
    }
}

impl_opaque_debug!(Serpent);
