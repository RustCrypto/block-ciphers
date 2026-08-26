//! Pure Rust implementation of the [Gift] block cipher.
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate implements only the low-level block cipher function, and is intended
//! for use for implementing higher-level constructions *only*. It is NOT
//! intended for direct use in applications.
//!
//! USE AT YOUR OWN RISK!
//!
//! # Examples
//! ```
//! use gift_cipher::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
//! use gift_cipher::Gift128;
//!
//! let key = Array::from([0u8; 16]);
//! let mut block = Array::from([0u8; 16]);
//!
//! // Initialize cipher
//! let cipher = Gift128::new(&key);
//!
//! let block_copy = block;
//!
//! // Encrypt block in-place
//! cipher.encrypt_block(&mut block);
//!
//! // And decrypt it back
//! cipher.decrypt_block(&mut block);
//!
//! assert_eq!(block, block_copy);
//! ```
//!
//! [Gift]: https://eprint.iacr.org/2017/622.pdf

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

use cipher::{
    AlgorithmName, Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, InOut, Key,
    KeyInit, KeySizeUser, ParBlocksSizeUser,
    consts::{U1, U16},
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

pub use cipher;

mod consts;
mod key_schedule;
mod primitives;

use consts::GIFT_RC;
use primitives::{inv_quintuple_round, packing, quintuple_round, unpacking};

/// Gift-128 block cipher instance.
#[derive(Clone)]
pub struct Gift128 {
    k: [u32; 80],
}

impl KeySizeUser for Gift128 {
    type KeySize = U16;
}

impl KeyInit for Gift128 {
    fn new(key: &Key<Self>) -> Self {
        Self {
            k: key_schedule::precompute_rkeys(key.into()),
        }
    }
}

impl BlockSizeUser for Gift128 {
    type BlockSize = U16;
}

impl ParBlocksSizeUser for Gift128 {
    type ParBlocksSize = U1;
}

impl BlockCipherEncrypt for Gift128 {
    #[inline]
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl BlockCipherEncBackend for Gift128 {
    #[inline]
    fn encrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let b = block.get_in();
        let mut state = [0u32; 4];
        packing(&mut state, b.into());
        for i in (0..40).step_by(5) {
            quintuple_round(&mut state, &self.k[i * 2..], &GIFT_RC[i..]);
        }
        unpacking(&state, block.get_out().into());
    }
}

impl BlockCipherDecrypt for Gift128 {
    #[inline]
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl BlockCipherDecBackend for Gift128 {
    #[inline]
    fn decrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let b = block.get_in();
        let mut state = [0u32; 4];
        packing(&mut state, b.into());
        let mut i: usize = 35;
        while i > 0 {
            inv_quintuple_round(&mut state, &self.k[i * 2..], &GIFT_RC[i..]);
            i -= 5;
        }
        inv_quintuple_round(&mut state, &self.k[i * 2..], &GIFT_RC[i..]);
        unpacking(&state, block.get_out().into());
    }
}

impl AlgorithmName for Gift128 {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Gift128")
    }
}

impl fmt::Debug for Gift128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Gift128 { ... }")
    }
}

impl Drop for Gift128 {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        self.k.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for Gift128 {}
