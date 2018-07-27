//! AES block cipher constant-time implementation.
//!
//! The `aes-soft` crate implements the AES algorithm completely in software
//! without using any table lookups or other timing dependant mechanisms.
//! The implementation is heavily based on `aessafe` [module][1]
//! from `rust-crypto` crate.
//!
//! # Usage example
//! ```
//! use aes_soft::block_cipher_trait::generic_array::GenericArray;
//! use aes_soft::block_cipher_trait::BlockCipher;
//! use aes_soft::Aes128;
//!
//! let key = GenericArray::from_slice(&[0u8; 16]);
//! let mut block = GenericArray::clone_from_slice(&[0u8; 16]);
//! let mut block8 = GenericArray::clone_from_slice(&[block; 8]);
//! // Initialize cipher
//! let cipher = aes_soft::Aes128::new(&key);
//!
//! let block_copy = block.clone();
//! // Encrypt block in-place
//! cipher.encrypt_block(&mut block);
//! // And decrypt it back
//! cipher.decrypt_block(&mut block);
//! assert_eq!(block, block_copy);
//!
//! // We can encrypt 8 blocks simultaneously using
//! // instruction-level parallelism
//! let block8_copy = block8.clone();
//! cipher.encrypt_blocks(&mut block8);
//! cipher.decrypt_blocks(&mut block8);
//! assert_eq!(block8, block8_copy);
//! ```
//! [1]: https://github.com/DaGenix/rust-crypto/blob/master/src/aessafe.rs
#![no_std]
pub extern crate block_cipher_trait;
extern crate byte_tools;
#[macro_use]
extern crate opaque_debug;

mod simd;
mod bitslice;
mod expand;
mod consts;
mod impls;

pub use impls::{Aes128, Aes192, Aes256};
