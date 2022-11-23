//! Implementation of the RC5-32/12/16 block cipher. Based on the [RC5 paper].
//!
//! ## WARNING
//! This crate implements the low-level RC5 block function. It is intended for implementing
//! higher level constructions. It is not intended for direct use in applications.
//!
//! [RC5 paper]: https://www.grc.com/r&d/rc5.pdf

mod block_cipher;
mod core;

pub use block_cipher::*;
