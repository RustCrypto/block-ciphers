//! Pure Rust implementation of the [Advanced Encryption Standard][AES]
//! (AES, a.k.a. Rijndael).
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate implements only the low-level block cipher function, and is intended
//! for use for implementing higher-level constructions *only*. It is NOT
//! intended for direct use in applications.
//!
//! USE AT YOUR OWN RISK!
//!
//! # Supported backends
//! This crate provides multiple backends including a portable pure Rust
//! backend as well as ones based on CPU intrinsics.
//!
//! By default, it performs runtime detection of CPU intrinsics and uses them
//! if they are available.
//!
//! ## "soft" portable backend
//! As a baseline implementation, this crate provides a constant-time pure Rust
//! implementation based on [fixslicing], a more advanced form of bitslicing
//! implemented entirely in terms of bitwise arithmetic with no use of any
//! lookup tables or data-dependent branches.
//!
//! Enabling the `compact` Cargo feature will reduce the code size of this
//! backend at the cost of decreased performance (using a modified form of
//! the fixslicing technique called "semi-fixslicing").
//!
//! ## ARMv8 intrinsics (nightly-only)
//! On `aarch64` targets including `aarch64-apple-darwin` (Apple M1) and Linux
//! targets such as `aarch64-unknown-linux-gnu` and `aarch64-unknown-linux-musl`,
//! support for using AES intrinsics provided by the ARMv8 Cryptography Extensions
//! is available when using the nightly compiler, and can be enabled using the
//! `armv8` crate feature.
//!
//! On Linux and macOS, when the `armv8` feature is enabled support for AES
//! intrinsics is autodetected at runtime. On other platforms the `aes`
//! target feature must be enabled via RUSTFLAGS.
//!
//! ## `x86`/`x86_64` intrinsics (AES-NI)
//! By default this crate uses runtime detection on `i686`/`x86_64` targets
//! in order to determine if AES-NI is available, and if it is not, it will
//! fallback to using a constant-time software implementation.
//!
//! Passing `RUSTFLAGS=-Ctarget-feature=+aes,+ssse3` explicitly at compile-time
//! will override runtime detection and ensure that AES-NI is always used.
//! Programs built in this manner will crash with an illegal instruction on
//! CPUs which do not have AES-NI enabled.
//!
//! Note: runtime detection is not possible on SGX targets. Please use the
//! afforementioned `RUSTFLAGS` to leverage AES-NI on these targets.
//!
//! # Examples
//! ```
//! use aes::Aes128;
//! use aes::cipher::{
//!     BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
//!     generic_array::GenericArray,
//! };
//!
//! let key = GenericArray::from([0u8; 16]);
//! let mut block = GenericArray::from([42u8; 16]);
//!
//! // Initialize cipher
//! let cipher = Aes128::new(&key);
//!
//! let block_copy = block.clone();
//!
//! // Encrypt block in-place
//! cipher.encrypt_block(&mut block);
//!
//! // And decrypt it back
//! cipher.decrypt_block(&mut block);
//! assert_eq!(block, block_copy);
//!
//! // implementation supports parrallel block processing
//! // number of blocks processed in parallel depends in general
//! // on hardware capabilities
//! let mut blocks = [block; 100];
//! cipher.encrypt_blocks(&mut blocks);
//!
//! for block in blocks.iter_mut() {
//!     cipher.decrypt_block(block);
//!     assert_eq!(block, &block_copy);
//! }
//!
//! cipher.decrypt_blocks(&mut blocks);
//!
//! for block in blocks.iter_mut() {
//!     cipher.encrypt_block(block);
//!     assert_eq!(block, &block_copy);
//! }
//! ```
//!
//! For implementation of block cipher modes of operation see
//! [`block-modes`] repository.
//!
//! # Configuration Flags
//!
//! You can modify crate using the following configuration flags:
//!
//! - `aes_armv8`: enable ARMv8 AES intrinsics (nightly-only).
//! - `aes_force_soft`: force software implementation.
//! - `aes_compact`: reduce code size at the cost of slower performance
//! (affects only software backend).
//!
//! It can be enabled using `RUSTFLAGS` enviromental variable
//! (e.g. `RUSTFLAGS="--cfg aes_compact"`) or by modifying `.cargo/config`.
//!
//! [AES]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
//! [fixslicing]: https://eprint.iacr.org/2020/1123.pdf
//! [AES-NI]: https://en.wikipedia.org/wiki/AES_instruction_set
//! [`block-modes`]: https://github.com/RustCrypto/block-modes/

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_root_url = "https://docs.rs/aes/0.8.1"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]
#![cfg_attr(
    all(aes_armv8, target_arch = "aarch64"),
    feature(stdsimd, aarch64_target_feature)
)]

#[cfg(feature = "hazmat")]
pub mod hazmat;

mod soft;

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(all(target_arch = "aarch64", aes_armv8, not(aes_force_soft)))] {
        mod armv8;
        mod autodetect;
        pub use autodetect::*;
    } else if #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        not(aes_force_soft)
    ))] {
        mod autodetect;
        mod ni;
        pub use autodetect::*;
    } else {
        pub use soft::*;
    }
}

pub use cipher;
use cipher::{
    consts::{U16, U8},
    generic_array::GenericArray,
};

/// 128-bit AES block
pub type Block = GenericArray<u8, U16>;
/// Eight 128-bit AES blocks
pub type Block8 = GenericArray<Block, U8>;
