//! Pure Rust implementation of the [Belt-block][belt-block]
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate implements only the low-level block cipher function, and is intended
//! for use for implementing higher-level constructions *only*. It is NOT
//! intended for direct use in applications.
//!
//! USE AT YOUR OWN RISK!
//!
//! [belt-block]: https://ru.wikipedia.org/wiki/BelT

pub use cipher;

mod consts;
mod block;

pub use crate::block::BeltBlock;
