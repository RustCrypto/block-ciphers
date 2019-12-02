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
use consts::{FP, IP, LT, LT_INVERSE, PHI, ROUNDS, S, S_INVERSE};

type Key = [u8; 16];
type Subkeys = [Key; ROUNDS + 1];
type Block128 = [u8; 16];
type Word = [u8; 16];

#[derive(Clone)]
pub struct Serpent {
    k: Subkeys, // Khat
}

fn get_word_bit(w: Word, i: usize) -> u8 {
    w[i / 8] >> (i % 8) & 0x01
}
fn get_bit(x: usize, i: usize) -> u8 {
    ((x >> i) & 0x01) as u8
}

fn set_bit(i: usize, v: u8, w: &mut Word) {
    // Fix this
    let index = i / 8;
    if v == 1 {
        w[index] |= 0x1 << (i % 8);
    } else {
        w[index] &= !(0x1 << (i % 8));
    }
}

fn permutate(t: [u8; 128], input: Block128) -> Block128 {
    let mut output = [0u8; 16];
    for (i, mv) in t.iter().enumerate() {
        let b = get_word_bit(input, *mv as usize);
        set_bit(i, b, &mut output);
    }
    output
}

fn linear_transform(input: Block128, output: &mut Block128) {
    *output = xor_table(LT, input);
}
fn linear_transform_inverse(output: Block128, input: &mut Block128) {
    *input = xor_table(LT_INVERSE, output);
}

fn round(
    i: usize,
    bhat_i: Block128,
    khat: Subkeys,
    bhat_output: &mut Block128,
) {
    let xored_block = xor_block(bhat_i, khat[i]);
    let shat_i = apply_shat(i, xored_block);
    if i <= ROUNDS - 2 {
        linear_transform(shat_i, bhat_output);
    } else if i == ROUNDS - 1 {
        *bhat_output = xor_block(shat_i, khat[ROUNDS]);
    } else {
        panic!("Encrypt: Round {} out of range", i);
    }
}

fn round_inverse(
    i: usize,
    bhat_i_next: Block128,
    khat: Subkeys,
    bhat_i: &mut Block128,
) {
    let (xored_block, shat_i) = &mut ([0u8; 16], [0u8; 16]);
    if i <= ROUNDS - 2 {
        linear_transform_inverse(bhat_i_next, shat_i);
    } else if i == ROUNDS - 1 {
        *shat_i = xor_block(bhat_i_next, khat[ROUNDS]);
    } else {
        panic!("Decrypt: Round {} out of range", i);
    }
    *xored_block = apply_shat_inverse(i, *shat_i);
    *bhat_i = xor_block(*xored_block, khat[i]);
}

fn apply_s(index: usize, nibble: u8) -> u8 {
    S[index % 8][nibble as usize]
}
fn apply_s_inverse(index: usize, nibble: u8) -> u8 {
    S_INVERSE[index % 8][nibble as usize]
}

fn apply_shat(b_i: usize, input: Block128) -> Block128 {
    let mut output: Block128 = [0u8; 16];
    for i in 0..16 {
        // 2 nibbles per byte
        for nibble_index in 0..2 {
            output[i] |= apply_s(b_i, (input[i] >> 4 * nibble_index) & 0xf)
                << (nibble_index * 4);
        }
    }
    output
}
fn apply_shat_inverse(b_i: usize, input: Block128) -> Block128 {
    let mut output: Block128 = [0u8; 16];
    for i in 0..16 {
        // 2 nibbles per byte
        for nibble_index in 0..2 {
            output[i] |=
                apply_s_inverse(b_i, (input[i] >> 4 * nibble_index) & 0xf)
                    << (nibble_index * 4);
        }
    }
    output
}

fn xor_block(b1: Block128, k: Key) -> Block128 {
    let mut xored: Block128 = [0u8; 16];
    for (i, _) in b1.iter().enumerate() {
        xored[i] = b1[i] ^ k[i];
    }
    xored
}
fn xor_table<'a>(t: [&'a [u8]; 128], input: Block128) -> Block128 {
    let mut xored: Block128 = [0u8; 16];
    for i in 0..128 {
        let _t = t[i];
        let mut b = 0usize;
        for table_value in _t.iter() {
            b ^= get_word_bit(input, *table_value as usize) as usize;
        }
        set_bit(i, b as u8, &mut xored);
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

        let words = &words[8..];
        let mut k = [0u32; 132];
        for i in 0..ROUNDS + 1 {
            let sbox_index = (ROUNDS + 3 - i) % ROUNDS;
            let a = words[(4 * i + 0) as usize];
            let b = words[(4 * i + 1) as usize];
            let c = words[(4 * i + 2) as usize];
            let d = words[(4 * i + 3) as usize];
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

        let r = ROUNDS + 1;
        let mut sub_keys: Subkeys = [[0u8; 16]; ROUNDS + 1];
        for i in 0..r {
            LE::write_u32(&mut sub_keys[i][..4], k[4 * i]);
            LE::write_u32(&mut sub_keys[i][4..8], k[4 * i + 1]);
            LE::write_u32(&mut sub_keys[i][8..12], k[4 * i + 2]);
            LE::write_u32(&mut sub_keys[i][12..], k[4 * i + 3]);
        }
        for sub_key in &mut sub_keys.iter_mut() {
            *sub_key = permutate(IP, *sub_key);
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

        LE::write_u128(&mut b, LE::read_u128(block.as_slice()));

        let mut bhat = permutate(IP, b);

        for i in 0..ROUNDS {
            round(i, bhat, self.k, &mut bhat);
        }

        let cipher = permutate(FP, bhat);

        *block = *GenericArray::from_slice(&cipher);
    }

    fn decrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
        let mut b = [0u8; 16];

        LE::write_u128(&mut b, LE::read_u128(block.as_slice()));

        // IP = FP inverse
        let mut bhat = permutate(IP, b);
        for i in (0..ROUNDS).rev() {
            round_inverse(i, bhat, self.k, &mut bhat);
        }
        // FP = IP inverse
        let plain = permutate(FP, bhat);

        *block = *GenericArray::from_slice(&plain);
    }
}

impl_opaque_debug!(Serpent);
