//! Pure Rust implementation of the Advanced Encryption Standard
//! (a.k.a. Rijndael)
//!
//! It provides two different backends based on what target features
//! are specified:
//!
//! - "soft" portable constant-time implementation based on [fixslicing].
//!   Enabling the `compact` Cargo feature will reduce the code size of this
//!   backend at the cost of decreased performance (using a modified form of
//!   the fixslicing technique called "semi-fixslicing").
//! - [AES-NI] accelerated implementation for `i686`/`x86_64` target
//!   architectures with `target-feature=+aes`, as well as an accelerated
//!   AES-CTR implementation with `target-feature=+aes,+ssse3`
//!
//! Crate switches between implementations automatically at compile time.
//! (i.e. it does not use run-time feature detection)
//!
//! # Usage example
//! ```
//! use aes::Aes128;
//! use aes::cipher::{
//!     BlockEncrypt, BlockDecrypt, KeyInit,
//!     generic_array::GenericArray,
//! };
//!
//! let key = GenericArray::from_slice(&[0u8; 16]);
//! let mut block = GenericArray::clone_from_slice(&[0u8; 16]);
//! // Initialize cipher
//! let cipher = Aes128::new(&key);
//!
//! let block_copy = block.clone();
//! // Encrypt block in-place
//! cipher.encrypt_block(&mut block);
//! // And decrypt it back
//! cipher.decrypt_block(&mut block);
//! assert_eq!(block, block_copy);
//!
//! // It's also possible to process data in buffer-to-buffer fashion
//! let mut res = GenericArray::default();
//! cipher.encrypt_block((&block, &mut res));
//! cipher.decrypt_block((&res, &mut block));
//! assert_eq!(block, block_copy);
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

pub use cipher::{self, BlockDecrypt, BlockEncrypt, KeyInit};

use cipher::generic_array::{GenericArray, typenum::{U16, U8, U2}};

type Block = GenericArray<u8, U16>;
type Block2 = GenericArray<Block, U2>;
type Block8 = GenericArray<Block, U8>;
