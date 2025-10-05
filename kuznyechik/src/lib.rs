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
//! You can modify crate using the `kuznyechik_backend` configuration flag.
//! It accepts the following values
//!
//! - `soft`: use software backend with big fused tables.
//! - `compact_soft`: use software backend with small tables and slower performance.
//!
//! The flag can be enabled using `RUSTFLAGS` environmental variable
//! (e.g. `RUSTFLAGS='--cfg kuznyechik_backend="soft"'`) or by modifying
//! `.cargo/config`.
//!
//! [Kuznyechik]: https://en.wikipedia.org/wiki/Kuznyechik
//! [GOST R 34.12-2015]: https://tc26.ru/standard/gost/GOST_R_3412-2015.pdf
#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]
#![allow(clippy::needless_range_loop, clippy::transmute_ptr_to_ptr)]

pub use cipher;
use cipher::{
    AlgorithmName, BlockSizeUser, KeyInit, KeySizeUser,
    array::Array,
    consts::{U16, U32},
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{ZeroizeOnDrop, zeroize_flat_type};

mod consts;
pub(crate) mod gft;
pub(crate) mod utils;

cfg_if::cfg_if!(
    if #[cfg(all(
        any(target_arch = "x86_64", target_arch = "x86"),
        target_feature = "sse2",
        not(any(kuznyechik_backend = "soft", kuznyechik_backend = "compact_soft")),
    ))] {
        mod fused_tables;
        mod sse2;
        use sse2 as imp;
    } else if #[cfg(all(
        target_arch = "aarch64",
        target_feature = "neon",
        not(any(kuznyechik_backend = "soft", kuznyechik_backend = "compact_soft")),
    ))] {
        mod fused_tables;
        mod neon;
        use neon as imp;
    } else if #[cfg(kuznyechik_backend = "compact_soft")] {
        mod compact_soft;
        use compact_soft as imp;
    } else {
        mod fused_tables;
        mod big_soft;
        use big_soft as imp;
    }
);

use imp::{DecKeys, EncDecKeys, EncKeys};

type BlockSize = U16;
type KeySize = U32;

/// 128-bit Kuznyechik block
pub type Block = Array<u8, U16>;
/// 256-bit Kuznyechik key
pub type Key = Array<u8, U32>;

/// Kuznyechik (GOST R 34.12-2015) block cipher
#[derive(Clone)]
pub struct Kuznyechik {
    keys: EncDecKeys,
}

impl KeySizeUser for Kuznyechik {
    type KeySize = KeySize;
}

impl BlockSizeUser for Kuznyechik {
    type BlockSize = BlockSize;
}

impl KeyInit for Kuznyechik {
    fn new(key: &Key) -> Self {
        let enc_keys = EncKeys::new(key);
        let keys = enc_keys.into();
        Self { keys }
    }
}

impl From<KuznyechikEnc> for Kuznyechik {
    #[inline]
    fn from(enc: KuznyechikEnc) -> Kuznyechik {
        let keys = enc.keys.clone().into();
        Self { keys }
    }
}

impl From<&KuznyechikEnc> for Kuznyechik {
    #[inline]
    fn from(enc: &KuznyechikEnc) -> Kuznyechik {
        let keys = enc.keys.clone().into();
        Self { keys }
    }
}

impl fmt::Debug for Kuznyechik {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("Kuznyechik { ... }")
    }
}

impl AlgorithmName for Kuznyechik {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Kuznyechik")
    }
}

impl Drop for Kuznyechik {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        unsafe {
            cipher::zeroize::zeroize_flat_type(self)
        }
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for Kuznyechik {}

/// Kuznyechik (GOST R 34.12-2015) block cipher (encrypt-only)
#[derive(Clone)]
pub struct KuznyechikEnc {
    keys: EncKeys,
}

impl KeySizeUser for KuznyechikEnc {
    type KeySize = KeySize;
}

impl BlockSizeUser for KuznyechikEnc {
    type BlockSize = BlockSize;
}

impl KeyInit for KuznyechikEnc {
    fn new(key: &Key) -> Self {
        let keys = EncKeys::new(key);
        Self { keys }
    }
}

impl fmt::Debug for KuznyechikEnc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("KuznyechikEnc { ... }")
    }
}

impl AlgorithmName for KuznyechikEnc {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Kuznyechik")
    }
}

impl Drop for KuznyechikEnc {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        unsafe {
            cipher::zeroize::zeroize_flat_type(self)
        }
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for KuznyechikEnc {}

/// Kuznyechik (GOST R 34.12-2015) block cipher (decrypt-only)
#[derive(Clone)]
pub struct KuznyechikDec {
    keys: DecKeys,
}

impl KeySizeUser for KuznyechikDec {
    type KeySize = KeySize;
}

impl BlockSizeUser for KuznyechikDec {
    type BlockSize = BlockSize;
}

impl KeyInit for KuznyechikDec {
    fn new(key: &Key) -> Self {
        let enc_keys = EncKeys::new(key);
        let keys = enc_keys.into();
        Self { keys }
    }
}

impl From<KuznyechikEnc> for KuznyechikDec {
    #[inline]
    fn from(enc: KuznyechikEnc) -> KuznyechikDec {
        let keys = enc.keys.clone().into();
        Self { keys }
    }
}

impl From<&KuznyechikEnc> for KuznyechikDec {
    #[inline]
    fn from(enc: &KuznyechikEnc) -> KuznyechikDec {
        let keys = enc.keys.clone().into();
        Self { keys }
    }
}

impl fmt::Debug for KuznyechikDec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("KuznyechikDec { ... }")
    }
}

impl AlgorithmName for KuznyechikDec {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Kuznyechik")
    }
}

impl Drop for KuznyechikDec {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        unsafe {
            zeroize_flat_type(self)
        }
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for KuznyechikDec {}
