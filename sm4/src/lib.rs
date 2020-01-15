//! An implementation of the [SM4][1] block cipher.
//!
//! [1]: https://en.wikipedia.org/wiki/SM4_(cipher)
#![no_std]
pub extern crate block_cipher_trait;
extern crate byteorder;

mod consts;
mod sm4;

use block_cipher_trait::generic_array;
use block_cipher_trait::BlockCipher;

pub use self::sm4::Sm4;
