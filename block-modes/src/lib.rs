//! This crate contains generic implementation of [block cipher modes of
//! operation][1].
//!
//! Note that this crate implements only modes which require padding. For CTR,
//! CFB and OFB modes (i.e. modes which transsform block ciphers into stream
//! ciphers) see crates in the [RustCrypto/stream-ciphers][2] repository.
//!
//! # Usage example
//! ```
//! #[macro_use] extern crate hex_literal;
//! extern crate aes_soft as aes;
//! extern crate block_modes;
//!
//! use block_modes::{BlockMode, Cbc};
//! use block_modes::block_padding::Pkcs7;
//! use aes::Aes128;
//!
//! // create an alias for convinience
//! type Aes128Cbc = Cbc<Aes128, Pkcs7>;
//!
//! # fn main() {
//! let key = hex!("000102030405060708090a0b0c0d0e0f");
//! let iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
//! let plaintext = b"Hello world!";
//! let cipher = Aes128Cbc::new_var(&key, &iv).unwrap();
//!
//! // buffer must have enough space for message+padding
//! let mut buffer = [0u8; 32];
//! // copy message to the buffer
//! let pos = plaintext.len();
//! buffer[..pos].copy_from_slice(plaintext);
//! let ciphertext = cipher.encrypt(&mut buffer, pos).unwrap();
//!
//! assert_eq!(ciphertext, hex!("1b7a4c403124ae2fb52bedc534d82fa8"));
//!
//! // re-create cipher mode instance
//! let cipher = Aes128Cbc::new_var(&key, &iv).unwrap();
//! let mut buf = ciphertext.to_vec();
//! let decrypted_ciphertext = cipher.decrypt(&mut buf).unwrap();
//!
//! assert_eq!(decrypted_ciphertext, plaintext);
//! # }
//! ```
//!
//! With an enabled `std` feature (which is enabled by default) you can use
//! `encrypt_vec` and `descrypt_vec` methods:
//! ```
//! # #[macro_use] extern crate hex_literal;
//! # extern crate aes_soft as aes;
//! # extern crate block_modes;
//! #
//! # use block_modes::{BlockMode, Cbc};
//! # use block_modes::block_padding::Pkcs7;
//! # use aes::Aes128;
//! #
//! # // create an alias for convinience
//! # type Aes128Cbc = Cbc<Aes128, Pkcs7>;
//! #
//! # fn main() {
//! # let key = hex!("000102030405060708090a0b0c0d0e0f");
//! # let iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
//! # let plaintext = b"Hello world!";
//! let cipher = Aes128Cbc::new_var(&key, &iv).unwrap();
//! let ciphertext = cipher.encrypt_vec(plaintext);
//!
//! assert_eq!(ciphertext, hex!("1b7a4c403124ae2fb52bedc534d82fa8"));
//!
//! let cipher = Aes128Cbc::new_var(&key, &iv).unwrap();
//! let decrypted_ciphertext = cipher.decrypt_vec(&ciphertext).unwrap();
//!
//! assert_eq!(decrypted_ciphertext, plaintext);
//! # }
//! ```
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
//! [2]: https://github.com/RustCrypto/stream-ciphers
#![no_std]
extern crate block_cipher_trait;
pub extern crate block_padding;
#[cfg(feature = "std")]
extern crate std;

mod utils;
mod traits;
mod errors;
pub use traits::BlockMode;
pub use errors::{BlockModeError, InvalidKeyIvLength};

mod cbc;
pub use cbc::Cbc;
mod ecb;
pub use ecb::Ecb;
mod pcbc;
pub use pcbc::Pcbc;
