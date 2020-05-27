//! Pure Rust implementation of the [DES cipher][1], including triple DES (3DES).
//!
//! [1]: https://en.wikipedia.org/wiki/Data_Encryption_Standard

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[macro_use]
extern crate opaque_debug;

pub use block_cipher;

mod consts;
mod des;
mod tdes;

pub use crate::des::Des;
pub use crate::tdes::{TdesEde2, TdesEde3, TdesEee2, TdesEee3};
