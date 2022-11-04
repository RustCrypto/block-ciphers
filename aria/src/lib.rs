//! Pure Rust implementation of the [ARIA] block cipher ([RFC 5794]).
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
//! use aria::cipher::generic_array::GenericArray;
//! use aria::cipher::{Key, Block, BlockEncrypt, BlockDecrypt, KeyInit};
//! use aria::Aria128;
//!
//! let key = GenericArray::from([0u8; 16]);
//! let mut block = GenericArray::from([0u8; 16]);
//! // Initialize cipher
//! let cipher = Aria128::new(&key);
//!
//! let block_copy = block.clone();
//! // Encrypt block in-place
//! cipher.encrypt_block(&mut block);
//! // And decrypt it back
//! cipher.decrypt_block(&mut block);
//! assert_eq!(block, block_copy);
//! ```
//!
//! [ARIA]: https://en.wikipedia.org/wiki/ARIA_(cipher)
//! [RFC 5794]: https://tools.ietf.org/html/rfc5794

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

mod consts;

pub use cipher;

use cipher::{
    consts::{U16, U24, U32},
    AlgorithmName, BlockCipher, Key, KeyInit, KeySizeUser,
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

use crate::consts::{C1, C2, C3, DIFFUSE_CONSTS, SB1, SB2, SB3, SB4};

#[inline(always)]
fn diffuse(x: [u8; 16]) -> u128 {
    DIFFUSE_CONSTS
        .iter()
        .zip(x)
        .map(|(a, b)| a * b as u128)
        .fold(0, |a, v| a ^ v)
}

#[inline(always)]
fn a(x128: u128) -> u128 {
    diffuse(x128.to_be_bytes())
}

fn sl2(x128: u128) -> u128 {
    let x = x128.to_be_bytes();
    let y = [
        SB3[x[0] as usize],
        SB4[x[1] as usize],
        SB1[x[2] as usize],
        SB2[x[3] as usize],
        SB3[x[4] as usize],
        SB4[x[5] as usize],
        SB1[x[6] as usize],
        SB2[x[7] as usize],
        SB3[x[8] as usize],
        SB4[x[9] as usize],
        SB1[x[10] as usize],
        SB2[x[11] as usize],
        SB3[x[12] as usize],
        SB4[x[13] as usize],
        SB1[x[14] as usize],
        SB2[x[15] as usize],
    ];
    u128::from_be_bytes(y)
}

fn fo(x128: u128) -> u128 {
    let x = x128.to_be_bytes();
    diffuse([
        SB1[x[0] as usize],
        SB2[x[1] as usize],
        SB3[x[2] as usize],
        SB4[x[3] as usize],
        SB1[x[4] as usize],
        SB2[x[5] as usize],
        SB3[x[6] as usize],
        SB4[x[7] as usize],
        SB1[x[8] as usize],
        SB2[x[9] as usize],
        SB3[x[10] as usize],
        SB4[x[11] as usize],
        SB1[x[12] as usize],
        SB2[x[13] as usize],
        SB3[x[14] as usize],
        SB4[x[15] as usize],
    ])
}

fn fe(x128: u128) -> u128 {
    let x = x128.to_be_bytes();
    diffuse([
        SB3[x[0] as usize],
        SB4[x[1] as usize],
        SB1[x[2] as usize],
        SB2[x[3] as usize],
        SB3[x[4] as usize],
        SB4[x[5] as usize],
        SB1[x[6] as usize],
        SB2[x[7] as usize],
        SB3[x[8] as usize],
        SB4[x[9] as usize],
        SB1[x[10] as usize],
        SB2[x[11] as usize],
        SB3[x[12] as usize],
        SB4[x[13] as usize],
        SB1[x[14] as usize],
        SB2[x[15] as usize],
    ])
}

impl KeyInit for Aria128 {
    fn new(key: &Key<Self>) -> Self {
        let kl = u128::from_be_bytes(key[0..16].try_into().unwrap());
        let kr = u128::default();

        let w0 = kl;
        let w1 = fo(w0 ^ C1) ^ kr;
        let w2 = fe(w1 ^ C2) ^ w0;
        let w3 = fo(w2 ^ C3) ^ w1;

        let ek = [
            w0 ^ w1.rotate_right(19),
            w1 ^ w2.rotate_right(19),
            w2 ^ w3.rotate_right(19),
            w3 ^ w0.rotate_right(19),
            w0 ^ w1.rotate_right(31),
            w1 ^ w2.rotate_right(31),
            w2 ^ w3.rotate_right(31),
            w3 ^ w0.rotate_right(31),
            w0 ^ w1.rotate_left(61),
            w1 ^ w2.rotate_left(61),
            w2 ^ w3.rotate_left(61),
            w3 ^ w0.rotate_left(61),
            w0 ^ w1.rotate_left(31),
        ];

        let dk = [
            ek[12],
            a(ek[11]),
            a(ek[10]),
            a(ek[9]),
            a(ek[8]),
            a(ek[7]),
            a(ek[6]),
            a(ek[5]),
            a(ek[4]),
            a(ek[3]),
            a(ek[2]),
            a(ek[1]),
            ek[0],
        ];

        Self { ek, dk }
    }
}

impl KeyInit for Aria192 {
    fn new(key: &Key<Self>) -> Self {
        let kl = u128::from_be_bytes(key[0..16].try_into().unwrap());
        let kr = u64::from_be_bytes(key[16..24].try_into().unwrap());
        let kr = (kr as u128) << 64;

        let w0 = kl;
        let w1 = fo(w0 ^ C2) ^ kr;
        let w2 = fe(w1 ^ C3) ^ w0;
        let w3 = fo(w2 ^ C1) ^ w1;

        let ek = [
            w0 ^ w1.rotate_right(19),
            w1 ^ w2.rotate_right(19),
            w2 ^ w3.rotate_right(19),
            w3 ^ w0.rotate_right(19),
            w0 ^ w1.rotate_right(31),
            w1 ^ w2.rotate_right(31),
            w2 ^ w3.rotate_right(31),
            w3 ^ w0.rotate_right(31),
            w0 ^ w1.rotate_left(61),
            w1 ^ w2.rotate_left(61),
            w2 ^ w3.rotate_left(61),
            w3 ^ w0.rotate_left(61),
            w0 ^ w1.rotate_left(31),
            w1 ^ w2.rotate_left(31),
            w2 ^ w3.rotate_left(31),
        ];

        let dk = [
            ek[14],
            a(ek[13]),
            a(ek[12]),
            a(ek[11]),
            a(ek[10]),
            a(ek[9]),
            a(ek[8]),
            a(ek[7]),
            a(ek[6]),
            a(ek[5]),
            a(ek[4]),
            a(ek[3]),
            a(ek[2]),
            a(ek[1]),
            ek[0],
        ];

        Self { ek, dk }
    }
}

impl KeyInit for Aria256 {
    fn new(key: &Key<Self>) -> Self {
        let kl = u128::from_be_bytes(key[0..16].try_into().unwrap());
        let kr = u128::from_be_bytes(key[16..32].try_into().unwrap());

        let w0 = kl;
        let w1 = fo(w0 ^ C3) ^ kr;
        let w2 = fe(w1 ^ C1) ^ w0;
        let w3 = fo(w2 ^ C2) ^ w1;

        let ek = [
            w0 ^ w1.rotate_right(19),
            w1 ^ w2.rotate_right(19),
            w2 ^ w3.rotate_right(19),
            w3 ^ w0.rotate_right(19),
            w0 ^ w1.rotate_right(31),
            w1 ^ w2.rotate_right(31),
            w2 ^ w3.rotate_right(31),
            w3 ^ w0.rotate_right(31),
            w0 ^ w1.rotate_left(61),
            w1 ^ w2.rotate_left(61),
            w2 ^ w3.rotate_left(61),
            w3 ^ w0.rotate_left(61),
            w0 ^ w1.rotate_left(31),
            w1 ^ w2.rotate_left(31),
            w2 ^ w3.rotate_left(31),
            w3 ^ w0.rotate_left(31),
            w0 ^ w1.rotate_left(19),
        ];

        let dk = [
            ek[16],
            a(ek[15]),
            a(ek[14]),
            a(ek[13]),
            a(ek[12]),
            a(ek[11]),
            a(ek[10]),
            a(ek[9]),
            a(ek[8]),
            a(ek[7]),
            a(ek[6]),
            a(ek[5]),
            a(ek[4]),
            a(ek[3]),
            a(ek[2]),
            a(ek[1]),
            ek[0],
        ];

        Self { ek, dk }
    }
}

macro_rules! impl_aria {
    ($name:ident, $subkey_size:literal, $key_size:ty, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name {
            /// Encrypting subkeys.
            ek: [u128; $subkey_size],
            /// Encrypting subkeys.
            dk: [u128; $subkey_size],
        }
        impl BlockCipher for $name {}

        impl KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }

        impl AlgorithmName for $name {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($name))
            }
        }

        #[cfg(feature = "zeroize")]
        #[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
        impl Drop for $name {
            fn drop(&mut self) {
                self.ek.zeroize();
                self.dk.zeroize();
            }
        }

        #[cfg(feature = "zeroize")]
        #[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
        impl ZeroizeOnDrop for $name {}

        cipher::impl_simple_block_encdec!(
            $name, U16, cipher, block,
            encrypt: {
                let mut p0 = u128::from_be_bytes((*block.get_in()).into());
                let mut p1;

                for i in (0..$subkey_size - 3).step_by(2) {
                    p1 = fo(p0 ^ cipher.ek[i]);
                    p0 = fe(p1 ^ cipher.ek[i + 1]);
                }

                let p1 = fo(p0 ^ cipher.ek[$subkey_size - 3]);
                let c = sl2(p1 ^ cipher.ek[$subkey_size - 2]) ^ cipher.ek[$subkey_size - 1];

                block.get_out().copy_from_slice(&c.to_be_bytes());
            }
            decrypt: {
                let mut c0 = u128::from_be_bytes((*block.get_in()).into());
                let mut c1;

                for i in (0..$subkey_size - 3).step_by(2) {
                    c1 = fo(c0 ^ cipher.dk[i]);
                    c0 = fe(c1 ^ cipher.dk[i + 1]);
                }

                let c1 = fo(c0 ^ cipher.dk[$subkey_size - 3]);
                let p = sl2(c1 ^ cipher.dk[$subkey_size - 2]) ^ cipher.dk[$subkey_size - 1];

                block.get_out().copy_from_slice(&p.to_be_bytes());
            }
        );

    };
}

impl_aria!(Aria128, 13, U16, "Aria-128 block cipher instance.");
impl_aria!(Aria192, 15, U24, "Aria-192 block cipher instance.");
impl_aria!(Aria256, 17, U32, "Aria-256 block cipher instance.");
