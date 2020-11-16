//! AES block ciphers implementation using AES-NI instruction set.
//!
//! This crate does not implement any software fallback and does not
//! automatically check CPUID, so if you are using this crate make sure to run
//! software on an appropriate hardware or to use software fallback
//! (e.g. from [`aes-soft`](https://crates.io/crates/aes-soft) crate) with
//! runtime detection of AES-NI availability (e.g. by using
//! [`cupid`](https://crates.io/crates/cupid) crate).
//!
//! When using this crate do not forget to enable `aes` target feature,
//! otherwise you will get a compilation error. You can do it either by using
//! `RUSTFLAGS="-C target-feature=+aes"` or by editing your `.cargo/config`.
//!
//! Ciphers functionality is accessed using `BlockCipher` trait from the
//! [`cipher`](https://docs.rs/cipher) crate.
//!
//! # CTR mode
//! In addition to core block cipher functionality this crate provides optimized
//! CTR mode implementation. This functionality requires additionall `ssse3`
//! target feature and feature-gated behind `ctr` feature flag, which is enabled
//! by default. If you only need block ciphers, disable default features with
//! `default-features = false` in your `Cargo.toml`.
//!
//! AES-CTR functionality is accessed using traits from
//! [`cipher`](https://docs.rs/cipher) crate.
//!
//! # Vulnerability
//! Lazy FP state restory vulnerability can allow local process to leak content
//! of the FPU register, in which round keys are stored. This vulnerability
//! can be mitigated at the operating system level by installing relevant
//! patches. (i.e. keep your OS updated!) More info:
//! - [Intel advisory](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00145.html)
//! - [Wikipedia](https://en.wikipedia.org/wiki/Lazy_FP_state_restore)
//!
//! # Runtime detection
//! If you plan to use AES with runtime detection (e.g. via
//! `is_x86_feature_detected!("aes")`), then you'll need to enable `nocheck`
//! feature to disable compile-time target checks. Note that techincally
//! doing so will make API of this crate unsafe, so you MUST ensure that
//! this crate will be used in contexts with enabled necessary target features!
//!
//! # Related documents
//!
//! - [Intel AES-NI whitepaper](https://software.intel.com/sites/default/files/article/165683/aes-wp-2012-09-22-v01.pdf)
//! - [Use of the AES Instruction Set](https://www.cosic.esat.kuleuven.be/ecrypt/AESday/slides/Use_of_the_AES_Instruction_Set.pdf)

#![allow(unsafe_code)]

#[macro_use]
mod utils;

mod aes128;
mod aes192;
mod aes256;

#[cfg(feature = "ctr")]
mod ctr;

#[cfg(not(feature = "nocheck"))]
mod target_checks;

#[cfg(target_arch = "x86")]
use core::arch::x86 as arch;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as arch;

pub use self::{aes128::Aes128, aes192::Aes192, aes256::Aes256};

#[cfg(feature = "ctr")]
pub use self::ctr::{Aes128Ctr, Aes192Ctr, Aes256Ctr};
