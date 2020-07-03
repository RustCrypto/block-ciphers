//! This crate contains generic implementation of [block cipher modes of
//! operation][1] defined in GOST R 34.13-2015.
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation

//#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
//#![deny(unsafe_code)]
//#![warn(missing_docs, rust_2018_idioms)]

pub use block_modes;
pub use stream_cipher;
pub use generic_array;
pub use block_modes::block_padding;
pub use block_modes::block_cipher::consts;

pub use block_modes::{BlockMode, Ecb};
pub use stream_cipher::{NewStreamCipher, SyncStreamCipher};

mod cbc;
mod cfb;
mod ctr;
mod ofb;
mod utils;

/// Block padding procedure number 2 as defined in GOST R 34.13-2015.
///
/// Fully equivalent to ISO 7816.
pub type GostPadding = block_padding::Iso7816;

pub use cfb::GostCfb;
pub use ofb::GostOfb;
pub use cbc::GostCbc;
pub use ctr::GostCtr;
