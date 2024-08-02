//! Pure Rust implementation of the [Kuznyechik] ([GOST R 34.12-2015]) block cipher.
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate implements only the low-level block cipher function, and is intended
//! for use for implementing higher-level constructions *only*. It is NOT
//! intended for direct use in applications.
//!
//! USE AT YOUR OWN RISK!
//!
//! # Configuration Flags
//!
//! You can modify crate using the following configuration flag:
//!
//! - `kuznyechik_force_soft`: force software implementation.
//! - `kuznyechik_compact_soft`: use compact software implementation.
//!
//! It can be enabled using `RUSTFLAGS` environmental variable
//! (e.g. `RUSTFLAGS="--cfg kuznyechik_force_soft"`) or by modifying
//! `.cargo/config`.
//!
//! [Kuznyechik]: https://en.wikipedia.org/wiki/Kuznyechik
//! [GOST R 34.12-2015]: https://tc26.ru/standard/gost/GOST_R_3412-2015.pdf
#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_docs, rust_2018_idioms)]
#![allow(clippy::needless_range_loop, clippy::transmute_ptr_to_ptr)]

pub use cipher;
use cipher::{
    array::Array,
    consts::{U16, U32},
};

mod consts;

cfg_if::cfg_if!(
    if #[cfg(all(
        any(target_arch = "x86_64", target_arch = "x86"),
        target_feature = "sse2",
        not(kuznyechik_force_soft),
    ))] {
        mod sse2;
        use sse2 as imp;
    } else if #[cfg(kuznyechik_compact_soft)] {
        mod compact_soft;
        use compact_soft as imp;
    } else {
        mod big_soft;
        use big_soft as imp;
    }
);

pub use imp::{Kuznyechik, KuznyechikDec, KuznyechikEnc};

type BlockSize = U16;
type KeySize = U32;

/// 128-bit Kuznyechik block
pub type Block = Array<u8, U16>;
/// 256-bit Kuznyechik key
pub type Key = Array<u8, U32>;
