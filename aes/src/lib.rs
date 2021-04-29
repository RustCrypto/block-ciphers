//! Pure Rust implementation of the Advanced Encryption Standard
//! (a.k.a. Rijndael)
//!
//! # Supported platforms
//!
//! This crate provides two different backends based on what target features
//! are available:
//!
//! - "soft" portable constant-time implementation based on [fixslicing].
//!   Enabling the `compact` Cargo feature will reduce the code size of this
//!   backend at the cost of decreased performance (using a modified form of
//!   the fixslicing technique called "semi-fixslicing").
//! - [AES-NI] accelerated implementation for `i686`/`x86_64` target
//!   architectures with `target-feature=+aes`, as well as an accelerated
//!   AES-CTR implementation with `target-feature=+aes,+ssse3`
//!
//! By default this crate uses runtime detection on `i686`/`x86_64` targets
//! in order to determine if AES-NI is available, and if it is not, it will
//! fallback to using a constant-time software implementation.
//!
//! Passing `RUSTFLAGS=-Ctarget-feature=+aes,+ssse3` explicitly at compile-time
//! will override runtime detection and ensure that AES-NI is always used.
//! Programs built in this manner will crash with an illegal instruction on
//! CPUs which do not have AES-NI enabled.
//!
//! # Usage example
//! ```
//! use aes::Aes128;
//! use aes::cipher::{
//!     BlockCipher, BlockEncrypt, BlockDecrypt, NewBlockCipher,
//!     generic_array::GenericArray,
//! };
//!
//! let key = GenericArray::from_slice(&[0u8; 16]);
//! let mut block = GenericArray::clone_from_slice(&[0u8; 16]);
//! let mut block8 = GenericArray::clone_from_slice(&[block; 8]);
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
//! // We can encrypt 8 blocks simultaneously using
//! // instruction-level parallelism
//! let block8_copy = block8.clone();
//! cipher.encrypt_par_blocks(&mut block8);
//! cipher.decrypt_par_blocks(&mut block8);
//! assert_eq!(block8, block8_copy);
//! ```
//!
//! For implementations of block cipher modes of operation see
//! [`block-modes`] crate.
//!
//! [fixslicing]: https://eprint.iacr.org/2020/1123.pdf
//! [AES-NI]: https://en.wikipedia.org/wiki/AES_instruction_set
//! [`block-modes`]: https://docs.rs/block-modes

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(all(
        any(target_arch = "x86_64", target_arch = "x86"),
        not(feature = "force-soft")
    ))] {
        mod autodetect;
        mod ni;
        mod soft;

        pub use autodetect::{Aes128, Aes192, Aes256};

        #[cfg(feature = "ctr")]
        pub use autodetect::ctr::{Aes128Ctr, Aes192Ctr, Aes256Ctr};
    } else {
        mod soft;
        pub use soft::{Aes128, Aes192, Aes256};

        #[cfg(feature = "ctr")]
        pub use soft::{Aes128Ctr, Aes192Ctr, Aes256Ctr};
    }
}

pub use cipher::{self, BlockCipher, BlockDecrypt, BlockEncrypt, NewBlockCipher};

/// 128-bit AES block
pub type Block = cipher::generic_array::GenericArray<u8, cipher::consts::U16>;

/// 8 x 128-bit AES blocks to be processed in parallel
pub type ParBlocks = cipher::generic_array::GenericArray<Block, cipher::consts::U8>;
