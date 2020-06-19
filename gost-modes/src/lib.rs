//! This crate contains generic implementation of [block cipher modes of
//! operation][1] defined in GOST R 34.13-2015.
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use block_modes;
pub use stream_cipher;
pub use block_modes::block_padding;

pub use block_modes::{BlockMode, Ecb};

mod ofb;
mod utils;

/// Block padding procedure number 1 as defined in GOST R 34.13-2015.
///
/// Fully equivalent to zero padding.
pub type GostPadding1 = block_padding::ZeroPadding;

/// Block padding procedure number 2 as defined in GOST R 34.13-2015.
///
/// Fully equivalent to ISO 7816.
pub type GostPadding2 = block_padding::Iso7816;
