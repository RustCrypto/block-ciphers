//! This crate contains generic implementation of [block cipher modes of
//! operation][1] defined in [GOST R 34.13-2015].
//!
//! Note that CTR, CFB and OFB modes are implemented in terms of traits from
//! the [`stream-cipher`] crate.
//!
//! MAC function defined in the GOST is implemented in the [`cmac`] crate.
//!
//! # Examples
//! ```
//! use gost_modes::{GostCbc, GostPadding, BlockMode, consts::U2};
//! use kuznyechik::Kuznyechik;
//! use hex_literal::hex;
//!
//! let key = hex!("
//!     8899aabbccddeeff0011223344556677
//!     fedcba98765432100123456789abcdef
//! ");
//! let iv = hex!("
//!     1234567890abcef0a1b2c3d4e5f00112
//!     23344556677889901213141516171819
//! ");
//! let pt = b"my secret message";
//!
//! type Cipher = GostCbc<Kuznyechik, GostPadding, U2>;
//!
//! let cipher = Cipher::new_var(&key, &iv).unwrap();
//! let ct = cipher.encrypt_vec(pt);
//!
//! let cipher = Cipher::new_var(&key, &iv).unwrap();
//! let buf = cipher.decrypt_vec(&ct).unwrap();
//!
//! assert_eq!(buf, &pt[..]);
//!
//! // OFB mode example
//! use gost_modes::{GostOfb, SyncStreamCipher, NewStreamCipher};
//!
//! let mut cipher = GostOfb::<Kuznyechik, U2>::new_var(&key, &iv).unwrap();
//! let mut buf = pt.to_vec();
//! cipher.apply_keystream(&mut buf);
//! assert_eq!(buf, hex!("fddb196e81812e4174d1c9f741a3457a88"));
//! ```
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
//! [GOST R 34.13-2015]: https://tc26.ru/standard/gost/GOST_R_3413-2015.pdf
//! [`stream-cipher`]: https://docs.rs/stream-cipher/
//! [`cmac`]: https://docs.rs/cmac/
#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use block_modes;
pub use block_modes::block_cipher::consts;
pub use block_modes::block_padding;
pub use generic_array;
pub use stream_cipher;

pub use block_modes::{BlockMode, Ecb};
pub use stream_cipher::{NewStreamCipher, SyncStreamCipher};

mod cbc;
mod cfb;
mod ctr;
mod ofb;
mod utils;

/// Block padding procedure number 2 as defined in GOST R 34.13-2015.
///
/// Fully equivalent to ISO 7816.
pub type GostPadding = block_padding::Iso7816;

pub use cbc::GostCbc;
pub use cfb::GostCfb;
pub use ctr::GostCtr;
pub use ofb::GostOfb;
