//! Pure Rust implementation of the [Gift][1] block cipher.
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
//! use gift::cipher::generic_array::GenericArray;
//! use gift::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
//! use gift::Gift128;
//!
//! let key = GenericArray::from([0u8; 16]);
//! let mut block = GenericArray::from([0u8; 16]);
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
//! [1]: https://eprint.iacr.org/2017/622.pdf

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_root_url = "https://docs.rs/gift/0.0.1"
)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

pub use cipher;

mod consts;
mod gift;
mod key_schedule;
mod primitives;

pub use crate::gift::Gift128;