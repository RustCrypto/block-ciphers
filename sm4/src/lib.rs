//! Pure Rust implementation of the [SM4] block cipher.
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate implements only the low-level block cipher function, and is intended
//! for use for implementing higher-level constructions *only*. It is NOT
//! intended for direct use in applications.
//!
//! USE AT YOUR OWN RISK!
//!
//! [SM4]: https://en.wikipedia.org/wiki/SM4_(cipher)

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

pub use cipher;

use cipher::{
    AlgorithmName, Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, InOut, Key,
    KeyInit, KeySizeUser, ParBlocksSizeUser,
    consts::{U1, U16},
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

mod consts;
use consts::{CK, FK, SBOX};

#[inline]
fn tau(a: u32) -> u32 {
    let mut buf = a.to_be_bytes();
    buf[0] = SBOX[buf[0] as usize];
    buf[1] = SBOX[buf[1] as usize];
    buf[2] = SBOX[buf[2] as usize];
    buf[3] = SBOX[buf[3] as usize];
    u32::from_be_bytes(buf)
}

/// L: linear transformation
#[inline]
fn el(b: u32) -> u32 {
    b ^ b.rotate_left(2) ^ b.rotate_left(10) ^ b.rotate_left(18) ^ b.rotate_left(24)
}

#[inline]
fn el_prime(b: u32) -> u32 {
    b ^ b.rotate_left(13) ^ b.rotate_left(23)
}

#[inline]
fn t(val: u32) -> u32 {
    el(tau(val))
}

#[inline]
fn t_prime(val: u32) -> u32 {
    el_prime(tau(val))
}

/// SM4 block cipher.
#[derive(Clone)]
pub struct Sm4 {
    rk: [u32; 32],
}

impl KeySizeUser for Sm4 {
    type KeySize = U16;
}

impl KeyInit for Sm4 {
    fn new(key: &Key<Self>) -> Self {
        let mk = [
            u32::from_be_bytes(key[0..4].try_into().unwrap()),
            u32::from_be_bytes(key[4..8].try_into().unwrap()),
            u32::from_be_bytes(key[8..12].try_into().unwrap()),
            u32::from_be_bytes(key[12..16].try_into().unwrap()),
        ];
        let mut rk = [0u32; 32];
        let mut k = [mk[0] ^ FK[0], mk[1] ^ FK[1], mk[2] ^ FK[2], mk[3] ^ FK[3]];

        for i in 0..8 {
            k[0] ^= t_prime(k[1] ^ k[2] ^ k[3] ^ CK[i * 4]);
            k[1] ^= t_prime(k[2] ^ k[3] ^ k[0] ^ CK[i * 4 + 1]);
            k[2] ^= t_prime(k[3] ^ k[0] ^ k[1] ^ CK[i * 4 + 2]);
            k[3] ^= t_prime(k[0] ^ k[1] ^ k[2] ^ CK[i * 4 + 3]);

            rk[i * 4] = k[0];
            rk[i * 4 + 1] = k[1];
            rk[i * 4 + 2] = k[2];
            rk[i * 4 + 3] = k[3];
        }

        Sm4 { rk }
    }
}

impl BlockSizeUser for Sm4 {
    type BlockSize = U16;
}

impl ParBlocksSizeUser for Sm4 {
    type ParBlocksSize = U1;
}

impl BlockCipherEncrypt for Sm4 {
    #[inline]
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl BlockCipherEncBackend for Sm4 {
    #[inline]
    fn encrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let b = block.get_in();
        let mut x = [
            u32::from_be_bytes(b[0..4].try_into().unwrap()),
            u32::from_be_bytes(b[4..8].try_into().unwrap()),
            u32::from_be_bytes(b[8..12].try_into().unwrap()),
            u32::from_be_bytes(b[12..16].try_into().unwrap()),
        ];

        let rk = &self.rk;
        for i in 0..8 {
            x[0] ^= t(x[1] ^ x[2] ^ x[3] ^ rk[i * 4]);
            x[1] ^= t(x[2] ^ x[3] ^ x[0] ^ rk[i * 4 + 1]);
            x[2] ^= t(x[3] ^ x[0] ^ x[1] ^ rk[i * 4 + 2]);
            x[3] ^= t(x[0] ^ x[1] ^ x[2] ^ rk[i * 4 + 3]);
        }

        let block = block.get_out();
        block[0..4].copy_from_slice(&x[3].to_be_bytes());
        block[4..8].copy_from_slice(&x[2].to_be_bytes());
        block[8..12].copy_from_slice(&x[1].to_be_bytes());
        block[12..16].copy_from_slice(&x[0].to_be_bytes());
    }
}

impl BlockCipherDecrypt for Sm4 {
    #[inline]
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl BlockCipherDecBackend for Sm4 {
    #[inline]
    fn decrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let b = block.get_in();
        let mut x = [
            u32::from_be_bytes(b[0..4].try_into().unwrap()),
            u32::from_be_bytes(b[4..8].try_into().unwrap()),
            u32::from_be_bytes(b[8..12].try_into().unwrap()),
            u32::from_be_bytes(b[12..16].try_into().unwrap()),
        ];

        let rk = &self.rk;
        for i in 0..8 {
            x[0] ^= t(x[1] ^ x[2] ^ x[3] ^ rk[31 - i * 4]);
            x[1] ^= t(x[2] ^ x[3] ^ x[0] ^ rk[31 - (i * 4 + 1)]);
            x[2] ^= t(x[3] ^ x[0] ^ x[1] ^ rk[31 - (i * 4 + 2)]);
            x[3] ^= t(x[0] ^ x[1] ^ x[2] ^ rk[31 - (i * 4 + 3)]);
        }

        let block = block.get_out();
        block[0..4].copy_from_slice(&x[3].to_be_bytes());
        block[4..8].copy_from_slice(&x[2].to_be_bytes());
        block[8..12].copy_from_slice(&x[1].to_be_bytes());
        block[12..16].copy_from_slice(&x[0].to_be_bytes());
    }
}

impl fmt::Debug for Sm4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sm4 { ... }")
    }
}

impl AlgorithmName for Sm4 {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sm4")
    }
}

impl Drop for Sm4 {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        self.rk.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for Sm4 {}
