//! Pure Rust implementation of the [Magma] block cipher defined in GOST 28147-89
//! and [GOST R 34.12-2015].
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate implements only the low-level block cipher function, and is intended
//! for use for implementing higher-level constructions *only*. It is NOT
//! intended for direct use in applications.
//!
//! USE AT YOUR OWN RISK!
//!
//! # Examples
//! ```
//! use magma::Magma;
//! use magma::cipher::{
//!     generic_array::GenericArray,
//!     BlockEncrypt, BlockDecrypt, KeyInit,
//! };
//! use hex_literal::hex;
//!
//! // Example vector from GOST 34.12-2018
//! let key = hex!(
//!     "FFEEDDCCBBAA99887766554433221100"
//!     "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"
//! );
//! let plaintext = hex!("FEDCBA9876543210");
//! let ciphertext = hex!("4EE901E5C2D8CA3D");
//!
//! let cipher = Magma::new(&key.into());
//!
//! let mut block = GenericArray::clone_from_slice(&plaintext);
//! cipher.encrypt_block(&mut block);
//! assert_eq!(&ciphertext, block.as_slice());
//!
//! cipher.decrypt_block(&mut block);
//! assert_eq!(&plaintext, block.as_slice());
//! ```
//!
//! [Magma]: https://en.wikipedia.org/wiki/GOST_(block_cipher)
//! [GOST R 34.12-2015]: https://tc26.ru/standard/gost/GOST_R_3412-2015.pdf
#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

pub use cipher;

use cipher::{
    consts::{U32, U8},
    AlgorithmName, BlockCipher, Key, KeyInit, KeySizeUser,
};
use core::{fmt, marker::PhantomData};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

mod sboxes;

pub use sboxes::Sbox;

/// Block cipher defined in GOST 28147-89 generic over S-box
#[derive(Clone)]
pub struct Gost89<S: Sbox> {
    key: [u32; 8],
    _p: PhantomData<S>,
}

impl<S: Sbox> BlockCipher for Gost89<S> {}

impl<S: Sbox> KeySizeUser for Gost89<S> {
    type KeySize = U32;
}

impl<S: Sbox> KeyInit for Gost89<S> {
    fn new(key: &Key<Self>) -> Self {
        let mut key_u32 = [0u32; 8];
        key.chunks_exact(4)
            .zip(key_u32.iter_mut())
            .for_each(|(chunk, v)| *v = to_u32(chunk));
        Self {
            key: key_u32,
            _p: PhantomData,
        }
    }
}

impl<S: Sbox> fmt::Debug for Gost89<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Gost89<")?;
        f.write_str(S::NAME)?;
        f.write_str("> { ... }")
    }
}

impl<S: Sbox> AlgorithmName for Gost89<S> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Gost89<")?;
        f.write_str(S::NAME)?;
        f.write_str("> { ... }")
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<S: Sbox> Drop for Gost89<S> {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<S: Sbox> ZeroizeOnDrop for Gost89<S> {}

cipher::impl_simple_block_encdec!(
    <S: Sbox> Gost89, U8, cipher, block,
    encrypt: {
        let b = block.get_in();
        let mut v = (to_u32(&b[0..4]), to_u32(&b[4..8]));
        for _ in 0..3 {
            for i in 0..8 {
                v = (v.1, v.0 ^ S::g(v.1, cipher.key[i]));
            }
        }
        for i in (0..8).rev() {
            v = (v.1, v.0 ^ S::g(v.1, cipher.key[i]));
        }
        let block = block.get_out();
        block[0..4].copy_from_slice(&v.1.to_be_bytes());
        block[4..8].copy_from_slice(&v.0.to_be_bytes());
    }
    decrypt: {
        let b = block.get_in();
        let mut v = (to_u32(&b[0..4]), to_u32(&b[4..8]));

        for i in 0..8 {
            v = (v.1, v.0 ^ S::g(v.1, cipher.key[i]));
        }

        for _ in 0..3 {
            for i in (0..8).rev() {
                v = (v.1, v.0 ^ S::g(v.1, cipher.key[i]));
            }
        }
        let block = block.get_out();
        block[0..4].copy_from_slice(&v.1.to_be_bytes());
        block[4..8].copy_from_slice(&v.0.to_be_bytes());
    }
);

/// Block cipher defined in GOST R 34.12-2015 (Magma)
pub type Magma = Gost89<sboxes::Tc26>;
/// Block cipher defined in GOST 28147-89 with test S-box
pub type Gost89Test = Gost89<sboxes::TestSbox>;
/// Block cipher defined in GOST 28147-89 with CryptoPro S-box version A
pub type Gost89CryptoProA = Gost89<sboxes::CryptoProA>;
/// Block cipher defined in GOST 28147-89 with CryptoPro S-box version B
pub type Gost89CryptoProB = Gost89<sboxes::CryptoProB>;
/// Block cipher defined in GOST 28147-89 with CryptoPro S-box version C
pub type Gost89CryptoProC = Gost89<sboxes::CryptoProC>;
/// Block cipher defined in GOST 28147-89 with CryptoPro S-box version D
pub type Gost89CryptoProD = Gost89<sboxes::CryptoProD>;

#[inline(always)]
fn to_u32(chunk: &[u8]) -> u32 {
    u32::from_be_bytes(chunk.try_into().unwrap())
}
