//! AES block cipher implementation using AES-NI instruction set.
//!
//! This crate does not implement any software fallback and does not
//! automatically check CPUID, so if you are using this crate make sure to run
//! software on an appropriate hardware or to use software fallback
//! (e.g. from [`aes-soft`](https://crates.io/crates/aes-soft) crate) with
//! runtime detection of AES-NI availability (e.g. by using
//! [`cupid`](https://crates.io/crates/cupid) crate).
//!
//! When using this crate do not forget to enable `aes` target feature,
//! otherwise you will get an empty crate. You can do it either by using
//! `RUSTFLAGS="-C target-feature=+aes"` or by editing your `.cargo/config`.
//! Alternatively you can enable `ignore_target_feature_check` crate feature
//! which will bypass target feature check, but it will have a negative implact
//! on performance.
//!
//! This crate currently requires nigthly Rust compiler due to the
//! usage of unstable `cfg_target_feature` and `stdsimd` features.
//!
//! Ciphers functionality is accessed using `BlockCipher` trait from
//! [`block-cipher-trait`](https://docs.rs/block-cipher-trait) crate.
//!
//! # Usage example
//! ```
//! # use aesni::block_cipher_trait::generic_array::GenericArray;
//! use aesni::{Aes128, BlockCipher};
//!
//! let key = GenericArray::from_slice(&[0u8; 16]);
//! let mut block = GenericArray::clone_from_slice(&[0u8; 16]);
//! let mut block8 = GenericArray::clone_from_slice(&[block; 8]);
//! // Initialize cipher
//! let cipher = aesni::Aes128::new(&key);
//!
//! let block_copy = block.clone();
//! // Encrypt block in-place
//! cipher.encrypt_block(&mut block);
//! // And decrypt it back
//! cipher.decrypt_block(&mut block);
//! assert_eq!(block, block_copy);
//!
//! // We can encrypt 8 blocks simultaneously using
//! // instruction-level parallelism
//! let block8_copy = block8.clone();
//! cipher.encrypt_blocks(&mut block8);
//! cipher.decrypt_blocks(&mut block8);
//! assert_eq!(block8, block8_copy);
//! ```
//!
//! # Related documents
//!
//! - [Intel AES-NI whitepaper](https://software.intel.com/sites/default/files/article/165683/aes-wp-2012-09-22-v01.pdf)
//! - [Use of the AES Instruction Set](https://www.cosic.esat.kuleuven.be/ecrypt/AESday/slides/Use_of_the_AES_Instruction_Set.pdf)
#![no_std]
#![feature(cfg_target_feature, stdsimd)]
#![cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#![cfg(any(target_feature = "aes", feature = "ignore_target_feature_check"))]
pub extern crate block_cipher_trait;
#[macro_use]
extern crate opaque_debug;

#[macro_use]
mod utils;
mod aes128;
mod aes192;
mod aes256;

pub use block_cipher_trait::BlockCipher;
pub use aes128::Aes128;
pub use aes192::Aes192;
pub use aes256::Aes256;
