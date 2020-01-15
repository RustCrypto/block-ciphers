//! An implementation of the [SM4][1] block cipher.
//!
//! [1]: https://en.wikipedia.org/wiki/SM4_(cipher)
#![no_std]
pub extern crate block_cipher_trait;

mod sm4;
mod consts;

use block_cipher_trait::BlockCipher;
use block_cipher_trait::generic_array;

pub use self::sm4::Sm4;
