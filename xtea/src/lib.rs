//! Pure Rust implementation of the [XTEA] block cipher.
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate implements only the low-level block cipher function, and is intended
//! for use for implementing higher-level constructions *only*. It is NOT
//! intended for direct use in applications.
//!
//! USE AT YOUR OWN RISK!
//!
//! [XTEA]: https://en.wikipedia.org/wiki/XTEA

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
    consts::{U16, U8},
    AlgorithmName, BlockCipher, InvalidLength, Key, KeyInit, KeySizeUser,
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

mod consts;
use consts::{DELTA, ROUNDS};

pub struct Xtea {
    key: [u32; 4],
}

impl BlockCipher for Xtea {}

impl KeySizeUser for Xtea {
    type KeySize = U16;
}

impl KeyInit for Xtea {
    fn new(key: &Key<Self>) -> Self {
        Self::new_from_slice(key).unwrap()
    }

    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        if key.len() != 16 {
            return Err(InvalidLength);
        }
        Ok(Xtea {
            key: [
                u32::from_le_bytes(key[0..4].try_into().unwrap()),
                u32::from_le_bytes(key[4..8].try_into().unwrap()),
                u32::from_le_bytes(key[8..12].try_into().unwrap()),
                u32::from_le_bytes(key[12..16].try_into().unwrap()),
            ],
        })
    }
}

impl fmt::Debug for Xtea {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XTEA { ... }")
    }
}

impl AlgorithmName for Xtea {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XTEA")
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl Drop for Xtea {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl ZeroizeOnDrop for Xtea {}

cipher::impl_simple_block_encdec!(
    Xtea, U8, cipher, block,
    encrypt: {
        let v = block.get_in();
        let mut v0 = u32::from_le_bytes(v[0..4].try_into().unwrap());
        let mut v1 = u32::from_le_bytes(v[4..8].try_into().unwrap());

        let mut sum = 0u32;
        for _ in 0..ROUNDS {
            v0 = v0.wrapping_add((((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1)) ^ (sum.wrapping_add(cipher.key[(sum & 3) as usize])));
            sum = sum.wrapping_add(DELTA);
            v1 = v1.wrapping_add((((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0)) ^ (sum.wrapping_add(cipher.key[((sum >> 11) & 3) as usize])));
        }

        let v = block.get_out();
        v[0..4].copy_from_slice(&v0.to_le_bytes());
        v[4..8].copy_from_slice(&v1.to_le_bytes());
    }
    decrypt: {
        let v = block.get_in();
        let mut v0 = u32::from_le_bytes(v[0..4].try_into().unwrap());
        let mut v1 = u32::from_le_bytes(v[4..8].try_into().unwrap());

        let mut sum = DELTA.wrapping_mul(ROUNDS);
        for _ in 0..ROUNDS {
            v1 = v1.wrapping_sub((((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0)) ^ (sum.wrapping_add(cipher.key[((sum >> 11) & 3) as usize])));
            sum = sum.wrapping_sub(DELTA);
            v0 = v0.wrapping_sub((((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1)) ^ (sum.wrapping_add(cipher.key[(sum & 3) as usize])));
        }

        let v = block.get_out();
        v[0..4].copy_from_slice(&v0.to_le_bytes());
        v[4..8].copy_from_slice(&v1.to_le_bytes());
    }
);
