//! AES block cipher implementation using AES-NI instruction set.
//!
//! This crate does not implement any software fallback and does not
//! automatically check CPUID, so if you are using this crate make sure to run
//! software on appropriate hardware or to check AES-NI availability using
//! `check_aesni()` function with an appropriate software fallback in case of
//! its unavailability.
//!
//! Additionally this crate currently requires nigthly Rust compiler due to the
//! usage of unstable `asm` and `simd` features.
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
#![cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#![no_std]
#![feature(repr_simd)]
#![feature(asm)]
pub extern crate block_cipher_trait;
#[macro_use]
extern crate opaque_debug;

mod aes128;
mod aes192;
mod aes256;
mod u64x2;
mod impl_traits;
mod ctr;

pub use aes128::Aes128;
pub use aes192::Aes192;
pub use aes256::Aes256;
pub use ctr::{CtrAes128, CtrAes192, CtrAes256};
pub use block_cipher_trait::BlockCipher;

/// Check if CPU has AES-NI using CPUID instruction.
///
/// It returns `true` if CPU has the instruction set, `false` otherwise.
#[inline]
pub fn check_aesni() -> bool {
    let ecx: u32;
    unsafe {
        asm!("cpuid"
            : "={ecx}"(ecx)
            : "{eax}"(1)
            : "edx", "ebx"
            : "intel"
        );
        (ecx & (1<<25)) != 0
    }
}
