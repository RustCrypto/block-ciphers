#![no_std]
pub extern crate block_cipher_trait;
extern crate byte_tools;
#[macro_use]
extern crate opaque_debug;

mod sboxes_exp;
#[macro_use]
mod construct;

pub use block_cipher_trait::BlockCipher;
use byte_tools::{read_u32_le, read_u32v_le, write_u32_le};
use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::generic_array::typenum::{U1, U32, U8};

use core::fmt;

use sboxes_exp::*;

type Block = GenericArray<u8, U8>;

#[derive(Clone, Copy)]
struct Gost89 {
    sbox: &'static SBoxExp,
    key: GenericArray<u32, U8>,
}

impl Gost89 {
    /*
    /// Switch S-box to a custom one
    fn switch_sbox(&self, sbox: &'a SBoxExp) -> Gost89<'a> {
        let mut cipher = *self;
        cipher.sbox = sbox;
        cipher
    }
    */

    fn apply_sbox(&self, a: u32) -> u32 {
        let mut v = 0;
        for i in 0..4 {
            let shft = 8 * i;
            let k = ((a & (0xffu32 << shft)) >> shft) as usize;
            v += (self.sbox[i][k] as u32) << shft;
        }
        v
    }

    fn g(&self, a: u32, k: u32) -> u32 {
        self.apply_sbox(a.wrapping_add(k)).rotate_left(11)
    }

    #[inline]
    fn encrypt(&self, block: &mut Block) {
        let mut v = (read_u32_le(&block[0..4]), read_u32_le(&block[4..8]));

        for _ in 0..3 {
            for i in (0..8).rev() {
                v = (v.1 ^ self.g(v.0, self.key[i]), v.0);
            }
        }
        for i in 0..8 {
            v = (v.1 ^ self.g(v.0, self.key[i]), v.0);
        }
        write_u32_le(&mut block[0..4], v.1);
        write_u32_le(&mut block[4..8], v.0);
    }

    #[inline]
    fn decrypt(&self, block: &mut Block) {
        let mut v = (read_u32_le(&block[0..4]), read_u32_le(&block[4..8]));

        for i in (0..8).rev() {
            v = (v.1 ^ self.g(v.0, self.key[i]), v.0);
        }

        for _ in 0..3 {
            for i in 0..8 {
                v = (v.1 ^ self.g(v.0, self.key[i]), v.0);
            }
        }
        write_u32_le(&mut block[0..4], v.1);
        write_u32_le(&mut block[4..8], v.0);
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
