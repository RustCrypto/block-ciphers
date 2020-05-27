//! Pure Rust implementation of the Kuznyechik (GOST R 34.12-2015) block cipher

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![allow(clippy::needless_range_loop, clippy::transmute_ptr_to_ptr)]

#[macro_use]
extern crate opaque_debug;

pub use block_cipher;

use block_cipher::generic_array::typenum::{U1, U16, U32};
use block_cipher::generic_array::GenericArray;
use block_cipher::{BlockCipher, NewBlockCipher};

mod consts;

type Block = GenericArray<u8, U16>;

/// Kuznyechik (GOST R 34.12-2015) block cipher
#[derive(Clone, Copy)]
pub struct Kuznyechik {
    keys: [[u8; 16]; 10],
}

fn x(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

fn l_step(msg: &mut [u8; 16], i: usize) {
    let mut x = msg[i];
    x ^= consts::GF[3][msg[(1 + i) & 0xf] as usize];
    x ^= consts::GF[1][msg[(2 + i) & 0xf] as usize];
    x ^= consts::GF[2][msg[(3 + i) & 0xf] as usize];
    x ^= consts::GF[0][msg[(4 + i) & 0xf] as usize];
    x ^= consts::GF[5][msg[(5 + i) & 0xf] as usize];
    x ^= consts::GF[4][msg[(6 + i) & 0xf] as usize];
    x ^= msg[(7 + i) & 0xf];
    x ^= consts::GF[6][msg[(8 + i) & 0xf] as usize];
    x ^= msg[(9 + i) & 0xf];
    x ^= consts::GF[4][msg[(10 + i) & 0xf] as usize];
    x ^= consts::GF[5][msg[(11 + i) & 0xf] as usize];
    x ^= consts::GF[0][msg[(12 + i) & 0xf] as usize];
    x ^= consts::GF[2][msg[(13 + i) & 0xf] as usize];
    x ^= consts::GF[1][msg[(14 + i) & 0xf] as usize];
    x ^= consts::GF[3][msg[(15 + i) & 0xf] as usize];
    msg[i] = x;
}

#[inline(always)]
fn lsx(msg: &mut [u8; 16], key: &[u8; 16]) {
    x(msg, key);
    // s
    for i in 0..16 {
        msg[i] = consts::P[msg[i] as usize];
    }
    // l
    for i in 0..16 {
        l_step(msg, i);
    }
}

fn lsx_inv(msg: &mut [u8; 16], key: &[u8; 16]) {
    x(msg, key);
    // l_inv
    for i in (0..16).rev() {
        l_step(msg, i);
    }
    // s_inv
    for i in 0..16 {
        msg[i] = consts::P_INV[msg[i] as usize];
    }
}

fn get_c(n: usize) -> [u8; 16] {
    let mut v = [0u8; 16];
    v[0] = n as u8;
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

        k1.copy_from_slice(&key[16..]);
        k2.copy_from_slice(&key[..16]);

        self.keys[0] = k1;
        self.keys[1] = k2;

        for i in 1..5 {
            f(&mut k1, &mut k2, i - 1);
            self.keys[2 * i] = k1;
            self.keys[2 * i + 1] = k2;
        }
    }

    fn encrypt(&self, msg: &mut [u8; 16]) {
        for k in &self.keys[..9] {
            lsx(msg, k);
        }
        x(msg, &self.keys[9])
    }

    fn decrypt(&self, msg: &mut [u8; 16]) {
        for k in self.keys[1..].iter().rev() {
            lsx_inv(msg, k);
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

impl_opaque_debug!(Kuznyechik);
