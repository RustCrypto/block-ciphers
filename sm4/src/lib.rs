//! Pure Rust implementation of the [SM4] block cipher.
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate implements only the low-level block cipher function, and is intended
//! for use for implementing higher-level constructions *only*. It is NOT
//! intended for direct use in applications.
//!
//! USE AT YOUR OWN RISK!
//!
//! [SM4]: https://en.wikipedia.org/wiki/SM4_(cipher)

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

use cfg_if::cfg_if;
pub use cipher;

mod consts;
mod soft;

cfg_if! {
    if #[cfg(all(target_arch = "aarch64", sm4_armv8, not(sm4_force_soft)))] {
        mod armv8;
        pub use self::armv8::autodetect::*;
    } else if #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        not(sm4_force_soft)
    ))] {
        mod x86;
        pub use self::x86::autodetect::*;
    } else {
        pub use soft::*;
    }
}
