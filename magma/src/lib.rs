#![no_std]
extern crate byte_tools;
extern crate block_cipher_trait;
extern crate generic_array;

mod sboxes_exp;
#[macro_use]
mod construct;

use byte_tools::{read_u32v_le, read_u32_le, write_u32_le};
use block_cipher_trait::{Block, BlockCipher, BlockCipherFixKey};
use generic_array::GenericArray;
use generic_array::typenum::{U8, U32};

use sboxes_exp::*;

#[derive(Clone,Copy)]
pub struct Gost89<'a> {
    sbox: &'a SBoxExp,
    key: GenericArray<u32, U8>,
}

impl<'a> Gost89<'a> {
    /// Create new cipher instance. Key interpreted as a 256 bit number
    /// in little-endian format
    pub fn new(key: &GenericArray<u8, U32>, sbox: &'a SBoxExp) -> Gost89<'a> {
        let mut cipher = Gost89{sbox: sbox, key: Default::default()};
        read_u32v_le(&mut cipher.key, key);
        cipher
    }

    fn apply_sbox(&self, a: u32) -> u32 {
        let mut v = 0;
        for i in 0..4 {
            let shft = 8*i;
            let k = ((a & (0xffu32 << shft) ) >> shft) as usize;
            v += (self.sbox[i][k] as u32) << shft;
        }
        v
    }

    fn g(&self, a: u32, k: u32) -> u32 {
        self.apply_sbox(a.wrapping_add(k)).rotate_left(11)
    }

    fn encrypt(&self, input: &Block<U8>, output: &mut Block<U8>) {
        let mut v = (read_u32_le(&input[0..4]), read_u32_le(&input[4..8]));

        for _ in 0..3 {
            for i in (0..8).rev() {
                v = (v.1 ^ self.g(v.0, self.key[i]), v.0);
            }
        }
        for i in 0..8 {
            v = (v.1 ^ self.g(v.0, self.key[i]), v.0);
        }
        write_u32_le(&mut output[0..4], v.1);
        write_u32_le(&mut output[4..8], v.0);
    }

    fn decrypt(&self, input: &Block<U8>, output: &mut Block<U8>) {
        let mut v = (read_u32_le(&input[0..4]), read_u32_le(&input[4..8]));

        for i in (0..8).rev() {
            v = (v.1 ^ self.g(v.0, self.key[i]), v.0);
        }

        for _ in 0..3 {
            for i in 0..8 {
                v = (v.1 ^ self.g(v.0, self.key[i]), v.0);
            }
        }
        write_u32_le(&mut output[0..4], v.1);
        write_u32_le(&mut output[4..8], v.0);
    }
}

impl<'a> BlockCipher for Gost89<'a> {
    type BlockSize = U8;

    fn encrypt_block(&self, input: &Block<U8>, output: &mut Block<U8>) {
        self.encrypt(input, output);
    }

    fn decrypt_block(&self, input: &Block<U8>, output: &mut Block<U8>) {
        self.decrypt(input, output);
    }
}

constuct_cipher!(Magma, S_TC26);
constuct_cipher!(Gost89Test, S_TEST);
constuct_cipher!(Gost89CryptoProA, S_CRYPTOPRO_A);
constuct_cipher!(Gost89CryptoProB, S_CRYPTOPRO_B);
constuct_cipher!(Gost89CryptoProC, S_CRYPTOPRO_C);
constuct_cipher!(Gost89CryptoProD, S_CRYPTOPRO_D);

#[cfg(test)]
mod sboxes;
#[cfg(test)]
mod gen_table;
