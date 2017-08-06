//! AES block cipher implementation using AES-NI instruction set.
//!
//! This crate does not implement any software fallback and does not check CPUID,
//! so if you are using this crate make sure you are running software on
//! appropriate hardware or using AES-NI detection and appropriate software
//! fallback.
//!
//! Additionally this crate currently requires nigthly Rust compiler due to the
//! usage of unstable `asm` and `simd` features.
//!
//! # Usage example
//! ```
//! let key = [0u8; 16];
//! let mut block = [0u8; 16];
//! let mut block8 = [0u8; 16*8];
//! // Initialize cipher
//! let cipher = aesni::Aes128::new(&key);
//! // Encrypt block in-place
//! cipher.encrypt(&mut block);
//! // And decrypt it back
//! cipher.decrypt(&mut block);
//! assert_eq!(block, [0u8; 16]);
//! // We can encrypt 8 blocks simultaneously using instruction-level parallelism
//! cipher.encrypt8(&mut block8);
//! cipher.decrypt8(&mut block8);
//! ```
//!
//! # Related documents
//!
//! - [Intel AES-NI whitepaper](https://software.intel.com/sites/default/files/article/165683/aes-wp-2012-09-22-v01.pdf)
//! - [Use of the AES Instruction Set](https://www.cosic.esat.kuleuven.be/ecrypt/AESday/slides/Use_of_the_AES_Instruction_Set.pdf)
#![cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#![no_std]
#![feature(repr_simd)]
#![feature(asm)]

mod aes128;
mod aes192;
mod aes256;
mod u64x2;

pub use aes128::Aes128;
pub use aes192::Aes192;
pub use aes256::Aes256;
