//! Pure Rust implementation of the [Extended Tiny Encryption Algorithm][XTEA].
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
    AlgorithmName, Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, InOut,
    InvalidLength, Key, KeyInit, KeySizeUser, ParBlocksSizeUser,
    consts::{U1, U8, U16},
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

mod consts;
use consts::{DELTA, ROUNDS};

/// XTEA block self.
pub struct Xtea {
    k: [u32; 4],
}

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
        let key = [
            u32::from_le_bytes(key[0..4].try_into().unwrap()),
            u32::from_le_bytes(key[4..8].try_into().unwrap()),
            u32::from_le_bytes(key[8..12].try_into().unwrap()),
            u32::from_le_bytes(key[12..16].try_into().unwrap()),
        ];
        Ok(Xtea { k: key })
    }
}

impl BlockSizeUser for Xtea {
    type BlockSize = U8;
}

impl ParBlocksSizeUser for Xtea {
    type ParBlocksSize = U1;
}

impl BlockCipherEncrypt for Xtea {
    #[inline]
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl BlockCipherEncBackend for Xtea {
    #[inline]
    fn encrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let v = block.get_in();
        let mut v0 = u32::from_le_bytes(v[0..4].try_into().unwrap());
        let mut v1 = u32::from_le_bytes(v[4..8].try_into().unwrap());
        let mut sum = 0u32;

        // Use 4 loops as otherwise unrolling will not be performed by default
        for _ in 0..8 {
            v0 = v0.wrapping_add(
                (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                    ^ sum.wrapping_add(self.k[(sum & 3) as usize]),
            );
            sum = sum.wrapping_add(DELTA);
            v1 = v1.wrapping_add(
                (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                    ^ sum.wrapping_add(self.k[((sum >> 11) & 3) as usize]),
            );
        }
        for _ in 0..8 {
            v0 = v0.wrapping_add(
                (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                    ^ sum.wrapping_add(self.k[(sum & 3) as usize]),
            );
            sum = sum.wrapping_add(DELTA);
            v1 = v1.wrapping_add(
                (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                    ^ sum.wrapping_add(self.k[((sum >> 11) & 3) as usize]),
            );
        }
        for _ in 0..8 {
            v0 = v0.wrapping_add(
                (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                    ^ sum.wrapping_add(self.k[(sum & 3) as usize]),
            );
            sum = sum.wrapping_add(DELTA);
            v1 = v1.wrapping_add(
                (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                    ^ sum.wrapping_add(self.k[((sum >> 11) & 3) as usize]),
            );
        }
        for _ in 0..8 {
            v0 = v0.wrapping_add(
                (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                    ^ sum.wrapping_add(self.k[(sum & 3) as usize]),
            );
            sum = sum.wrapping_add(DELTA);
            v1 = v1.wrapping_add(
                (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                    ^ sum.wrapping_add(self.k[((sum >> 11) & 3) as usize]),
            );
        }

        let v = block.get_out();
        v[0..4].copy_from_slice(&v0.to_le_bytes());
        v[4..8].copy_from_slice(&v1.to_le_bytes());
    }
}

impl BlockCipherDecrypt for Xtea {
    #[inline]
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl BlockCipherDecBackend for Xtea {
    #[inline]
    fn decrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let v = block.get_in();
        let mut v0 = u32::from_le_bytes(v[0..4].try_into().unwrap());
        let mut v1 = u32::from_le_bytes(v[4..8].try_into().unwrap());
        let mut sum = DELTA.wrapping_mul(ROUNDS as u32);

        // Same as encrypt, just in reverse
        for _ in 0..8 {
            v1 = v1.wrapping_sub(
                (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                    ^ sum.wrapping_add(self.k[((sum >> 11) & 3) as usize]),
            );
            sum = sum.wrapping_sub(DELTA);
            v0 = v0.wrapping_sub(
                (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                    ^ sum.wrapping_add(self.k[(sum & 3) as usize]),
            );
        }
        for _ in 0..8 {
            v1 = v1.wrapping_sub(
                (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                    ^ sum.wrapping_add(self.k[((sum >> 11) & 3) as usize]),
            );
            sum = sum.wrapping_sub(DELTA);
            v0 = v0.wrapping_sub(
                (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                    ^ sum.wrapping_add(self.k[(sum & 3) as usize]),
            );
        }
        for _ in 0..8 {
            v1 = v1.wrapping_sub(
                (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                    ^ sum.wrapping_add(self.k[((sum >> 11) & 3) as usize]),
            );
            sum = sum.wrapping_sub(DELTA);
            v0 = v0.wrapping_sub(
                (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                    ^ sum.wrapping_add(self.k[(sum & 3) as usize]),
            );
        }
        for _ in 0..8 {
            v1 = v1.wrapping_sub(
                (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                    ^ sum.wrapping_add(self.k[((sum >> 11) & 3) as usize]),
            );
            sum = sum.wrapping_sub(DELTA);
            v0 = v0.wrapping_sub(
                (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                    ^ sum.wrapping_add(self.k[(sum & 3) as usize]),
            );
        }

        let v = block.get_out();
        v[0..4].copy_from_slice(&v0.to_le_bytes());
        v[4..8].copy_from_slice(&v1.to_le_bytes());
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

impl Drop for Xtea {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        self.k.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for Xtea {}
