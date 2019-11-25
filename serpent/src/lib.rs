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

use block_cipher_trait::generic_array::typenum::{U1, U16, U32};
use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::BlockCipher;
use block_cipher_trait::InvalidKeyLength;
use byteorder::{ByteOrder, LE};

mod consts;
use consts::{IP, LT, PHI, ROUNDS, S};

type Key = [u8; 16];
type Subkeys = [Key; ROUNDS + 1];
type Block128 = [u8; 16];
type Word = [u8; 16];

struct Serpent {
    k: Subkeys, // Khat
}

fn get_word_bit(w: Word, i: usize) -> u8 {
    (w[i / 32] >> (i % 32)) & 0x01
}
fn get_bit(x: usize, i: usize) -> u8 {
    ((x >> i) & 0x01) as u8
}

fn set_bit(w: &mut Word, i: usize, v: usize) {
    if (v & 0x01) == 1 {
        w[i / 32 as usize] |= 1 << i;
    } else {
        w[i / 32 as usize] &= !(1 << i);
    }
}

fn permutate(t: [u8; 128], input: Block128, output: &mut Block128) {
    for (i, mv) in t.iter().enumerate() {
        let b = get_word_bit(input, *mv as usize);
        set_bit(output, i as usize, b as usize);
    }
}

fn linear_transform(input: Block128, output: &mut Block128) {
    *output = xor_table(LT, input);
}

fn round(
    i: usize,
    bhat_i: Block128,
    khat: Subkeys,
    bhat_output: &mut Block128,
) {
    let xored_block = xor_block(bhat_i, khat[i]);
    let shat_i = apply_shat(i, xored_block);
    if i <= 0 && i <= ROUNDS - 2 {
        linear_transform(shat_i, bhat_output);
    }
}

fn apply_s(index: usize, nibble: u8) -> u8 {
    S[index % 8][nibble as usize]
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
        set_bit(&mut xored, i as usize, b);
    }
    xored
}

impl Serpent {
    fn key_schedule(key: &[u8]) -> Subkeys {
        let mut words = [0u32; 132];
        LE::read_u32_into(&key, &mut words[..8]);

        for i in 0..131 {
            let slot = i + 8;
            words[slot] = (words[slot - 8]
                ^ words[slot - 5]
                ^ words[slot - 3]
                ^ words[slot - 1]
                ^ PHI
                ^ i as u32)
                .rotate_left(11);
        }

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
                for l in 0..3 {
                    k[(4 * i + l) as usize] |=
                        u32::from(get_bit(output as usize, l) << j);
                }
            }
        }

        let r = ROUNDS + 1;
        let mut sub_keys: Subkeys = [[0u8; 16]; ROUNDS + 1];
        for i in 0..r {
            LE::write_u32(&mut sub_keys[i][..3], k[4 * i]);
            LE::write_u32(&mut sub_keys[i][4..7], k[4 * i + 1]);
            LE::write_u32(&mut sub_keys[i][8..11], k[4 * i + 2]);
            LE::write_u32(&mut sub_keys[i][12..], k[4 * i + 3]);
        }
        for sub_key in &mut sub_keys[..] {
            permutate(IP, *sub_key, sub_key);
        }

        sub_keys
    }
}

impl BlockCipher for Serpent {
    type KeySize = U32;
    type BlockSize = U16;
    type ParBlocks = U1;
    fn new(key: &GenericArray<u8, U32>) -> Self {
        Self::new_varkey(key).unwrap()
    }

    fn new_varkey(key: &[u8]) -> Result<Self, InvalidKeyLength> {
        Ok(Serpent {
            k: Serpent::key_schedule(key),
        })
    }

    fn encrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
        let mut b = [0u8; 16];

        LE::write_u128(&mut b, LE::read_u128(block.as_slice()));

        let bhat = &mut [0u8; 16];
        permutate(IP, b, bhat);

        for i in 0..ROUNDS {
            round(i, *bhat, self.k, bhat);
        }
    }

    fn decrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
        unimplemented!()
    }
}

impl_opaque_debug!(Serpent);
