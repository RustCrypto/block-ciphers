//! AES block cipher constant-time implementation.
//!
//! The implementation uses a technique called [fixslicing][1], an improved
//! form of bitslicing which represents ciphers in a way which enables
//! very efficient constant-time implementations in software.
//!
//! [1]: https://eprint.iacr.org/2020/1123.pdf

#![deny(unsafe_code)]

#[cfg_attr(not(target_pointer_width = "64"), path = "soft/fixslice32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "soft/fixslice64.rs")]
mod fixslice;
mod impls;

#[cfg(feature = "ctr")]
mod ctr;

pub use self::impls::{Aes128, Aes192, Aes256};

#[cfg(feature = "ctr")]
pub use self::ctr::{Aes128Ctr, Aes192Ctr, Aes256Ctr};
