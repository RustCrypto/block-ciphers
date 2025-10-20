//! Pure Rust implementation of the [ARIA] block cipher ([RFC 5794]).
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
//! use aria::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
//! use aria::Aria128;
//!
//! let key = Array::from([0u8; 16]);
//! let mut block = Array::from([0u8; 16]);
//! // Initialize cipher
//! let cipher = Aria128::new(&key);
//!
//! let block_copy = block.clone();
//! // Encrypt block in-place
//! cipher.encrypt_block(&mut block);
//! // And decrypt it back
//! cipher.decrypt_block(&mut block);
//! assert_eq!(block, block_copy);
//! ```
//!
//! [ARIA]: https://en.wikipedia.org/wiki/ARIA_(cipher)
//! [RFC 5794]: https://tools.ietf.org/html/rfc5794

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

mod consts;

pub use cipher;

use cipher::{
    Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt, BlockCipherEncBackend,
    BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, ParBlocksSizeUser,
    consts::{U1, U16},
    inout::InOut,
};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

mod aria128;
mod aria192;
mod aria256;
mod utils;

use utils::{fe, fo, sl2};

/// Generic implementation of the ARIA block cipher.
///
/// It can be initialized only with `RK` being equal to 13 (ARIA-128),
/// 15 (ARIA-192), or 17 (ARIA-256).
#[derive(Clone)]
pub struct Aria<const RK: usize> {
    /// Encrypting subkeys.
    ek: [u128; RK],
    /// Encrypting subkeys.
    dk: [u128; RK],
}

impl<const RK: usize> BlockSizeUser for Aria<RK> {
    type BlockSize = U16;
}

impl<const RK: usize> ParBlocksSizeUser for Aria<RK> {
    type ParBlocksSize = U1;
}

impl<const RK: usize> BlockCipherEncrypt for Aria<RK> {
    #[inline]
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl<const RK: usize> BlockCipherEncBackend for Aria<RK> {
    #[inline]
    fn encrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut p0 = u128::from_be_bytes((*block.get_in()).into());
        let mut p1;

        for i in (0..RK - 3).step_by(2) {
            p1 = fo(p0 ^ self.ek[i]);
            p0 = fe(p1 ^ self.ek[i + 1]);
        }

        let p1 = fo(p0 ^ self.ek[RK - 3]);
        let c = sl2(p1 ^ self.ek[RK - 2]) ^ self.ek[RK - 1];

        block.get_out().copy_from_slice(&c.to_be_bytes());
    }
}

impl<const RK: usize> BlockCipherDecrypt for Aria<RK> {
    #[inline]
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl<const RK: usize> BlockCipherDecBackend for Aria<RK> {
    #[inline]
    fn decrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut c0 = u128::from_be_bytes((*block.get_in()).into());
        let mut c1;

        for i in (0..RK - 3).step_by(2) {
            c1 = fo(c0 ^ self.dk[i]);
            c0 = fe(c1 ^ self.dk[i + 1]);
        }

        let c1 = fo(c0 ^ self.dk[RK - 3]);
        let p = sl2(c1 ^ self.dk[RK - 2]) ^ self.dk[RK - 1];

        block.get_out().copy_from_slice(&p.to_be_bytes());
    }
}

impl<const RK: usize> Drop for Aria<RK> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.ek.zeroize();
            self.dk.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl<const RK: usize> ZeroizeOnDrop for Aria<RK> {}

/// ARIA-128 block cipher instance.
pub type Aria128 = Aria<13>;
/// ARIA-192 block cipher instance.
pub type Aria192 = Aria<15>;
/// ARIA-256 block cipher instance.
pub type Aria256 = Aria<17>;
