//! Pure Rust implementation of the [Kuznyechik][1] (GOST R 34.12-2015) block cipher.
//!
//! [1]: https://en.wikipedia.org/wiki/Kuznyechik
#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![allow(clippy::needless_range_loop, clippy::transmute_ptr_to_ptr)]

pub use cipher;

use cipher::{
    consts::{U1, U16, U32},
    generic_array::GenericArray,
    BlockCipher, NewBlockCipher,
};

mod consts;
#[macro_use]
mod macros;

type Block = GenericArray<u8, U16>;

/// Kuznyechik (GOST R 34.12-2015) block cipher
#[derive(Clone, Copy)]
pub struct Kuznyechik {
    keys: [[u8; 16]; 10],
}

#[inline(always)]
fn x(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

fn l_step(msg: &mut [u8; 16], i: usize) {
    #[inline(always)]
    fn get_idx(b: usize, i: usize) -> usize {
        b.wrapping_sub(i) & 0x0F
    }
    #[inline(always)]
    fn get_m(msg: &[u8; 16], b: usize, i: usize) -> usize {
        msg[get_idx(b, i)] as usize
    }

    let mut x = msg[get_idx(15, i)];
    x ^= consts::GF[3][get_m(msg, 14, i)];
    x ^= consts::GF[1][get_m(msg, 13, i)];
    x ^= consts::GF[2][get_m(msg, 12, i)];
    x ^= consts::GF[0][get_m(msg, 11, i)];
    x ^= consts::GF[5][get_m(msg, 10, i)];
    x ^= consts::GF[4][get_m(msg, 9, i)];
    x ^= msg[get_idx(8, i)];
    x ^= consts::GF[6][get_m(msg, 7, i)];
    x ^= msg[get_idx(6, i)];
    x ^= consts::GF[4][get_m(msg, 5, i)];
    x ^= consts::GF[5][get_m(msg, 4, i)];
    x ^= consts::GF[0][get_m(msg, 3, i)];
    x ^= consts::GF[2][get_m(msg, 2, i)];
    x ^= consts::GF[1][get_m(msg, 1, i)];
    x ^= consts::GF[3][get_m(msg, 0, i)];
    msg[get_idx(15, i)] = x;
}

#[inline(always)]
fn lsx(msg: &mut [u8; 16], key: &[u8; 16]) {
    x(msg, key);
    // s
    unroll16! {i, { msg[i] = consts::P[msg[i] as usize]; }};
    // l
    unroll16! {i, { l_step(msg, i) }};
}

#[inline(always)]
fn lsx_inv(msg: &mut [u8; 16], key: &[u8; 16]) {
    x(msg, key);
    // l_inv
    unroll16! {i, { l_step(msg, 15 - i) }};
    // s_inv
    unroll16! {i, { msg[15 - i] = consts::P_INV[msg[15 - i] as usize]; }};
}

fn get_c(n: usize) -> [u8; 16] {
    let mut v = [0u8; 16];
    v[15] = n as u8;
    for i in 0..16 {
        l_step(&mut v, i);
    }
    v
}

fn f(k1: &mut [u8; 16], k2: &mut [u8; 16], n: usize) {
    for i in 0..4 {
        let mut k1_cpy = *k1;
        lsx(&mut k1_cpy, &get_c(8 * n + 2 * i + 1));
        x(k2, &k1_cpy);

        let mut k2_cpy = *k2;
        lsx(&mut k2_cpy, &get_c(8 * n + 2 * i + 2));
        x(k1, &k2_cpy);
    }
}

impl Kuznyechik {
    fn expand_key(&mut self, key: &GenericArray<u8, U32>) {
        let mut k1 = [0u8; 16];
        let mut k2 = [0u8; 16];

        k1.copy_from_slice(&key[..16]);
        k2.copy_from_slice(&key[16..]);

        self.keys[0] = k1;
        self.keys[1] = k2;

        for i in 1..5 {
            f(&mut k1, &mut k2, i - 1);
            self.keys[2 * i] = k1;
            self.keys[2 * i + 1] = k2;
        }
    }

    fn encrypt(&self, msg: &mut [u8; 16]) {
        unroll9! {
            i, { lsx(msg, &self.keys[i]) ; }
        }
        x(msg, &self.keys[9])
    }

    fn decrypt(&self, msg: &mut [u8; 16]) {
        unroll9! {
            i, { lsx_inv(msg, &self.keys[9 - i]) ; }
        }
        x(msg, &self.keys[0])
    }
}

impl NewBlockCipher for Kuznyechik {
    type KeySize = U32;

    fn new(key: &GenericArray<u8, U32>) -> Self {
        let mut cipher = Self {
            keys: Default::default(),
        };
        cipher.expand_key(key);
        cipher
    }
}

impl BlockCipher for Kuznyechik {
    type BlockSize = U16;
    type ParBlocks = U1;

    #[inline]
    fn encrypt_block(&self, block: &mut Block) {
        #[allow(unsafe_code)]
        let block: &mut [u8; 16] = unsafe { core::mem::transmute(block) };
        self.encrypt(block);
    }

    #[inline]
    fn decrypt_block(&self, block: &mut Block) {
        #[allow(unsafe_code)]
        let block: &mut [u8; 16] = unsafe { core::mem::transmute(block) };
        self.decrypt(block);
    }
}

opaque_debug::implement!(Kuznyechik);
