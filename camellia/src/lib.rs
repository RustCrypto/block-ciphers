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
//! use camellia::cipher::generic_array::GenericArray;
//! use camellia::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
//! use camellia::Camellia128;
//!
//! let key = GenericArray::from([0_u8; 16]);
//! let mut block = GenericArray::from([0_u8; 16]);
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

pub use cipher;

mod camellia;
mod consts;

pub use crate::camellia::{Camellia128, Camellia192, Camellia256};
