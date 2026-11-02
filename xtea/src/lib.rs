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
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(unsafe_code)]

pub use cipher;

use cipher::{
    AlgorithmName, Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, InOut, Key,
    KeyInit, KeySizeUser, ParBlocksSizeUser,
    consts::{U1, U8, U16},
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

mod consts;
use consts::{DELTA, ROUNDS};

/// XTEA block self.
pub struct Xtea {
    key: [u32; 4],
}

impl KeySizeUser for Xtea {
    type KeySize = U16;
}

impl KeyInit for Xtea {
    #[inline]
    fn new(key: &Key<Self>) -> Self {
        let key = read_u32_le(key);
        Self { key }
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
        f.call(self);
    }
}

impl BlockCipherEncBackend for Xtea {
    #[inline]
    fn encrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let [mut v0, mut v1] = read_u32_le(block.get_in());
        let mut sum = 0u32;

        // Use 4 loops as otherwise unrolling will not be performed by default
        for _ in 0..8 {
            v0 = v0.wrapping_add(
                (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                    ^ sum.wrapping_add(self.key[(sum & 3) as usize]),
            );
            sum = sum.wrapping_add(DELTA);
            v1 = v1.wrapping_add(
                (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                    ^ sum.wrapping_add(self.key[((sum >> 11) & 3) as usize]),
            );
        }
        for _ in 0..8 {
            v0 = v0.wrapping_add(
                (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                    ^ sum.wrapping_add(self.key[(sum & 3) as usize]),
            );
            sum = sum.wrapping_add(DELTA);
            v1 = v1.wrapping_add(
                (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                    ^ sum.wrapping_add(self.key[((sum >> 11) & 3) as usize]),
            );
        }
        for _ in 0..8 {
            v0 = v0.wrapping_add(
                (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                    ^ sum.wrapping_add(self.key[(sum & 3) as usize]),
            );
            sum = sum.wrapping_add(DELTA);
            v1 = v1.wrapping_add(
                (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                    ^ sum.wrapping_add(self.key[((sum >> 11) & 3) as usize]),
            );
        }
        for _ in 0..8 {
            v0 = v0.wrapping_add(
                (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                    ^ sum.wrapping_add(self.key[(sum & 3) as usize]),
            );
            sum = sum.wrapping_add(DELTA);
            v1 = v1.wrapping_add(
                (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                    ^ sum.wrapping_add(self.key[((sum >> 11) & 3) as usize]),
            );
        }

        write_u32_le(block.get_out(), [v0, v1]);
    }
}

impl BlockCipherDecrypt for Xtea {
    #[inline]
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
        f.call(self);
    }
}

impl BlockCipherDecBackend for Xtea {
    #[inline]
    fn decrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let [mut v0, mut v1] = read_u32_le(block.get_in());
        let mut sum = DELTA.wrapping_mul(ROUNDS);

        // Same as encrypt, just in reverse
        for _ in 0..8 {
            v1 = v1.wrapping_sub(
                (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                    ^ sum.wrapping_add(self.key[((sum >> 11) & 3) as usize]),
            );
            sum = sum.wrapping_sub(DELTA);
            v0 = v0.wrapping_sub(
                (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                    ^ sum.wrapping_add(self.key[(sum & 3) as usize]),
            );
        }
        for _ in 0..8 {
            v1 = v1.wrapping_sub(
                (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                    ^ sum.wrapping_add(self.key[((sum >> 11) & 3) as usize]),
            );
            sum = sum.wrapping_sub(DELTA);
            v0 = v0.wrapping_sub(
                (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                    ^ sum.wrapping_add(self.key[(sum & 3) as usize]),
            );
        }
        for _ in 0..8 {
            v1 = v1.wrapping_sub(
                (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                    ^ sum.wrapping_add(self.key[((sum >> 11) & 3) as usize]),
            );
            sum = sum.wrapping_sub(DELTA);
            v0 = v0.wrapping_sub(
                (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                    ^ sum.wrapping_add(self.key[(sum & 3) as usize]),
            );
        }
        for _ in 0..8 {
            v1 = v1.wrapping_sub(
                (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                    ^ sum.wrapping_add(self.key[((sum >> 11) & 3) as usize]),
            );
            sum = sum.wrapping_sub(DELTA);
            v0 = v0.wrapping_sub(
                (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1))
                    ^ sum.wrapping_add(self.key[(sum & 3) as usize]),
            );
        }

        write_u32_le(block.get_out(), [v0, v1]);
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
        self.key.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for Xtea {}

fn read_u32_le<const N: usize>(src: &[u8]) -> [u32; N] {
    assert_eq!(size_of_val(src), size_of::<[u32; N]>());
    let (chunks, tail) = src.as_chunks();
    assert!(tail.is_empty());
    core::array::from_fn(|i| u32::from_le_bytes(chunks[i]))
}

fn write_u32_le<const N: usize>(dst: &mut [u8], val: [u32; N]) {
    assert_eq!(size_of_val(dst), size_of_val(&val));
    let (chunks, tail) = dst.as_chunks_mut();
    assert!(tail.is_empty());
    for i in 0..N {
        chunks[i] = val[i].to_le_bytes();
    }
}
