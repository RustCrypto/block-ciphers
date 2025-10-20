//! Pure Rust implementation of the [Camellia][1] block cipher.
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
//! use camellia::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
//! use camellia::Camellia128;
//!
//! let key = Array::from([0_u8; 16]);
//! let mut block = Array::from([0_u8; 16]);
//!
//! // Initialize cipher
//! let cipher = Camellia128::new(&key);
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
//! [1]: https://en.wikipedia.org/wiki/Camellia_(cipher)

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

use core::marker::PhantomData;

pub use cipher;

use cipher::{
    Block, BlockSizeUser, KeySizeUser, ParBlocksSizeUser,
    array::ArraySize,
    block::{
        BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt, BlockCipherEncBackend,
        BlockCipherEncClosure, BlockCipherEncrypt,
    },
    consts::{U1, U16, U24, U32},
    inout::InOut,
};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

mod camellia128;
mod camellia192;
mod camellia256;
mod consts;
mod utils;

use utils::{f, fl, flinv};

/// Generic implementation of the Camellia block cipher.
///
/// This type can be initialized only with 3 combinations of `KeySize` and `RK`:
/// - Camellia-128: U16, 26
/// - Camellia-192: U24, 34
/// - Camellia-256: U32, 34
#[derive(Clone)]
pub struct Camellia<KeySize: ArraySize, const RK: usize> {
    k: [u64; RK],
    _pd: PhantomData<KeySize>,
}

/// Camellia-128 block cipher instance.
pub type Camellia128 = Camellia<U16, 26>;
/// Camellia-192 block cipher instance.
pub type Camellia192 = Camellia<U24, 34>;
/// Camellia-256 block cipher instance.
pub type Camellia256 = Camellia<U32, 34>;

impl<KeySize: ArraySize, const RK: usize> KeySizeUser for Camellia<KeySize, RK> {
    type KeySize = KeySize;
}

impl<KeySize: ArraySize, const RK: usize> BlockSizeUser for Camellia<KeySize, RK> {
    type BlockSize = U16;
}

impl<KeySize: ArraySize, const RK: usize> ParBlocksSizeUser for Camellia<KeySize, RK> {
    type ParBlocksSize = U1;
}

impl<KeySize: ArraySize, const RK: usize> BlockCipherEncrypt for Camellia<KeySize, RK> {
    #[inline]
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl<KeySize: ArraySize, const RK: usize> BlockCipherEncBackend for Camellia<KeySize, RK> {
    #[inline]
    fn encrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let b = block.get_in();
        let mut d1 = u64::from_be_bytes(b[0..8].try_into().unwrap());
        let mut d2 = u64::from_be_bytes(b[8..16].try_into().unwrap());

        d1 ^= self.k[0];
        d2 ^= self.k[1];

        for i in (2..RK - 2).step_by(2) {
            if i % 8 == 0 {
                d1 = fl(d1, self.k[i]);
                d2 = flinv(d2, self.k[i + 1]);

                continue;
            }
            d2 ^= f(d1, self.k[i]);
            d1 ^= f(d2, self.k[i + 1]);
        }

        d2 ^= self.k[RK - 2];
        d1 ^= self.k[RK - 1];

        let (b1, b2) = block.get_out().split_at_mut(8);
        b1.copy_from_slice(&d2.to_be_bytes());
        b2.copy_from_slice(&d1.to_be_bytes());
    }
}

impl<KeySize: ArraySize, const RK: usize> BlockCipherDecrypt for Camellia<KeySize, RK> {
    #[inline]
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl<KeySize: ArraySize, const RK: usize> BlockCipherDecBackend for Camellia<KeySize, RK> {
    #[inline]
    fn decrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let b = block.get_in();
        let mut d1 = u64::from_be_bytes(b[0..8].try_into().unwrap());
        let mut d2 = u64::from_be_bytes(b[8..16].try_into().unwrap());

        d2 ^= self.k[RK - 1];
        d1 ^= self.k[RK - 2];

        for i in (2..RK - 2).rev().step_by(2) {
            if (i - 1) % 8 == 0 {
                d1 = fl(d1, self.k[i]);
                d2 = flinv(d2, self.k[i - 1]);

                continue;
            }
            d2 ^= f(d1, self.k[i]);
            d1 ^= f(d2, self.k[i - 1]);
        }

        d1 ^= self.k[1];
        d2 ^= self.k[0];

        let (b1, b2) = block.get_out().split_at_mut(8);
        b1.copy_from_slice(&d2.to_be_bytes());
        b2.copy_from_slice(&d1.to_be_bytes());
    }
}

impl<KeySize: ArraySize, const RK: usize> Drop for Camellia<KeySize, RK> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        self.k.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<KeySize: ArraySize, const RK: usize> ZeroizeOnDrop for Camellia<KeySize, RK> {}
