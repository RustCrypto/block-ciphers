//! Pure Rust implementation of the [IDEA] block cipher.
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate implements only the low-level block cipher function, and is intended
//! for use for implementing higher-level constructions *only*. It is NOT
//! intended for direct use in applications.
//!
//! USE AT YOUR OWN RISK!
//!
//! [IDEA]: https://en.wikipedia.org/wiki/International_Data_Encryption_Algorithm

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_root_url = "https://docs.rs/idea/0.5.1"
)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]
#![allow(clippy::many_single_char_names)]

pub use cipher;

use cipher::{
    consts::{U16, U8},
    inout::InOut,
    AlgorithmName, Block, BlockCipher, Key, KeyInit, KeySizeUser,
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

mod consts;
#[cfg(test)]
mod tests;

use consts::{FUYI, LENGTH_SUB_KEYS, MAXIM, ONE, ROUNDS};

/// The International Data Encryption Algorithm (IDEA) block cipher.
#[derive(Clone)]
pub struct Idea {
    enc_keys: [u16; LENGTH_SUB_KEYS],
    dec_keys: [u16; LENGTH_SUB_KEYS],
}

impl Idea {
    fn expand_key(&mut self, key: &Key<Self>) {
        let length_key = key.len();
        for i in 0..(length_key / 2) {
            self.enc_keys[i] = (u16::from(key[2 * i]) << 8) + u16::from(key[2 * i + 1]);
        }

        let mut a: u16;
        let mut b: u16;
        for i in (length_key / 2)..LENGTH_SUB_KEYS {
            if (i + 1) % 8 == 0 {
                a = self.enc_keys[i - 15];
            } else {
                a = self.enc_keys[i - 7];
            }

            if (i + 2) % 8 < 2 {
                b = self.enc_keys[i - 14];
            } else {
                b = self.enc_keys[i - 6];
            }

            self.enc_keys[i] = (a << 9) + (b >> 7);
        }
    }

    fn invert_sub_keys(&mut self) {
        let mut k = ROUNDS * 6;
        for i in 0..=ROUNDS {
            let j = i * 6;
            let l = k - j;

            let (m, n) = if i > 0 && i < 8 { (2, 1) } else { (1, 2) };

            self.dec_keys[j] = self.mul_inv(self.enc_keys[l]);
            self.dec_keys[j + 1] = self.add_inv(self.enc_keys[l + m]);
            self.dec_keys[j + 2] = self.add_inv(self.enc_keys[l + n]);
            self.dec_keys[j + 3] = self.mul_inv(self.enc_keys[l + 3]);
        }

        k = (ROUNDS - 1) * 6;
        for i in 0..ROUNDS {
            let j = i * 6;
            let l = k - j;
            self.dec_keys[j + 4] = self.enc_keys[l + 4];
            self.dec_keys[j + 5] = self.enc_keys[l + 5];
        }
    }

    fn crypt(&self, mut block: InOut<'_, '_, Block<Self>>, sub_keys: &[u16; LENGTH_SUB_KEYS]) {
        let b = block.get_in();
        let mut x1 = u16::from_be_bytes(b[0..2].try_into().unwrap());
        let mut x2 = u16::from_be_bytes(b[2..4].try_into().unwrap());
        let mut x3 = u16::from_be_bytes(b[4..6].try_into().unwrap());
        let mut x4 = u16::from_be_bytes(b[6..8].try_into().unwrap());

        for i in 0..ROUNDS {
            let j = i * 6;
            let y1 = self.mul(x1, sub_keys[j]);
            let y2 = self.add(x2, sub_keys[j + 1]);
            let y3 = self.add(x3, sub_keys[j + 2]);
            let y4 = self.mul(x4, sub_keys[j + 3]);

            let t0 = self.mul(y1 ^ y3, sub_keys[j + 4]);
            let _t = self.add(y2 ^ y4, t0);
            let t1 = self.mul(_t, sub_keys[j + 5]);
            let t2 = self.add(t0, t1);

            x1 = y1 ^ t1;
            x2 = y3 ^ t1;
            x3 = y2 ^ t2;
            x4 = y4 ^ t2;
        }

        let y1 = self.mul(x1, sub_keys[48]);
        let y2 = self.add(x3, sub_keys[49]);
        let y3 = self.add(x2, sub_keys[50]);
        let y4 = self.mul(x4, sub_keys[51]);

        let block = block.get_out();
        block[0..2].copy_from_slice(&y1.to_be_bytes());
        block[2..4].copy_from_slice(&y2.to_be_bytes());
        block[4..6].copy_from_slice(&y3.to_be_bytes());
        block[6..8].copy_from_slice(&y4.to_be_bytes());
    }

    fn mul(&self, a: u16, b: u16) -> u16 {
        let x = u32::from(a);
        let y = u32::from(b);
        let mut r: i32;

        if x == 0 {
            r = (MAXIM - y) as i32;
        } else if y == 0 {
            r = (MAXIM - x) as i32;
        } else {
            let c: u32 = x * y;
            r = ((c & ONE) as i32) - ((c >> 16) as i32);
            if r < 0 {
                r += MAXIM as i32;
            }
        }

        (r & (ONE as i32)) as u16
    }

    fn add(&self, a: u16, b: u16) -> u16 {
        ((u32::from(a) + u32::from(b)) & ONE) as u16
    }

    fn mul_inv(&self, a: u16) -> u16 {
        if a <= 1 {
            a
        } else {
            let mut x = u32::from(a);
            let mut y = MAXIM;
            let mut t0 = 1u32;
            let mut t1 = 0u32;
            loop {
                t1 += y / x * t0;
                y %= x;
                if y == 1 {
                    return (MAXIM - t1) as u16;
                }
                t0 += x / y * t1;
                x %= y;
                if x == 1 {
                    return t0 as u16;
                }
            }
        }
    }

    fn add_inv(&self, a: u16) -> u16 {
        ((FUYI - (u32::from(a))) & ONE) as u16
    }
}

impl BlockCipher for Idea {}

impl KeySizeUser for Idea {
    type KeySize = U16;
}

impl KeyInit for Idea {
    fn new(key: &Key<Self>) -> Self {
        let mut cipher = Self {
            enc_keys: [0u16; 52],
            dec_keys: [0u16; 52],
        };
        cipher.expand_key(key);
        cipher.invert_sub_keys();
        cipher
    }
}

impl fmt::Debug for Idea {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Idea { ... }")
    }
}

impl AlgorithmName for Idea {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Idea")
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl Drop for Idea {
    fn drop(&mut self) {
        self.enc_keys.zeroize();
        self.dec_keys.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl ZeroizeOnDrop for Idea {}

cipher::impl_simple_block_encdec!(
    Idea, U8, cipher, block,
    encrypt: {
        cipher.crypt(block, &cipher.enc_keys);
    }
    decrypt: {
        cipher.crypt(block, &cipher.dec_keys);
    }
);
