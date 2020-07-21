//! Pure Rust implementation of the [Magma][1] (GOST 28147-89) block cipher.
//!
//! [1]: https://en.wikipedia.org/wiki/GOST_(block_cipher)
#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![deny(unsafe_code)]
#![warn(rust_2018_idioms)]

mod sboxes_exp;
#[macro_use]
mod construct;

pub use block_cipher;

use block_cipher::consts::{U1, U32, U8};
use block_cipher::generic_array::GenericArray;
use block_cipher::{BlockCipher, NewBlockCipher};
use byteorder::{ByteOrder, BE};

use crate::sboxes_exp::*;

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
        let mut v = (BE::read_u32(&block[0..4]), BE::read_u32(&block[4..8]));
        for _ in 0..3 {
            for i in 0..8 {
                v = (v.1, v.0 ^ self.g(v.1, self.key[i]));
            }
        }
        for i in (0..8).rev() {
            v = (v.1, v.0 ^ self.g(v.1, self.key[i]));
        }
        BE::write_u32(&mut block[0..4], v.1);
        BE::write_u32(&mut block[4..8], v.0);
    }

    #[inline]
    fn decrypt(&self, block: &mut Block) {
        let mut v = (BE::read_u32(&block[0..4]), BE::read_u32(&block[4..8]));

        for i in 0..8 {
            v = (v.1, v.0 ^ self.g(v.1, self.key[i]));
        }

        for _ in 0..3 {
            for i in (0..8).rev() {
                v = (v.1, v.0 ^ self.g(v.1, self.key[i]));
            }
        }
        BE::write_u32(&mut block[0..4], v.1);
        BE::write_u32(&mut block[4..8], v.0);
    }
}

construct_cipher!(Magma, S_TC26);
construct_cipher!(Gost89Test, S_TEST);
construct_cipher!(Gost89CryptoProA, S_CRYPTOPRO_A);
construct_cipher!(Gost89CryptoProB, S_CRYPTOPRO_B);
construct_cipher!(Gost89CryptoProC, S_CRYPTOPRO_C);
construct_cipher!(Gost89CryptoProD, S_CRYPTOPRO_D);

#[cfg(test)]
mod gen_table;
#[cfg(test)]
mod sboxes;
