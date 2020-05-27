//! CAST5 block cipher.
//!
//! Implementation according to [RFC 2144](https://tools.ietf.org/html/rfc2144).
//!
//!
//! # Usage example
//! ```
//! use cast5::block_cipher::generic_array::GenericArray;
//! use cast5::block_cipher::{BlockCipher, NewBlockCipher};
//! use cast5::Cast5;
//!
//! let key = GenericArray::from_slice(&[0u8; 16]);
//! let mut block = GenericArray::clone_from_slice(&[0u8; 8]);
//! // Initialize cipher
//! let cipher = Cast5::new(&key);
//!
//! let block_copy = block.clone();
//! // Encrypt block in-place
//! cipher.encrypt_block(&mut block);
//! // And decrypt it back
//! cipher.decrypt_block(&mut block);
//! assert_eq!(block, block_copy);
//! ```

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use block_cipher;

#[macro_use]
extern crate opaque_debug;

pub use block_cipher::BlockCipher;

mod cast5;
mod consts;
mod schedule;

pub use crate::cast5::Cast5;
