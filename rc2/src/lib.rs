//! Pure Rust implementation of the [RC2] block cipher.
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate implements only the low-level block cipher function, and is intended
//! for use for implementing higher-level constructions *only*. It is NOT
//! intended for direct use in applications.
//!
//! USE AT YOUR OWN RISK!
//!
//! [RC2]: https://en.wikipedia.org/wiki/RC2

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_root_url = "https://docs.rs/rc2/0.8.1"
)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

pub use cipher;

use cipher::{
    consts::{U32, U8},
    AlgorithmName, BlockCipher, InvalidLength, Key, KeyInit, KeySizeUser,
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

mod consts;
use crate::consts::PI_TABLE;

/// A structure that represents the block cipher initialized with a key
#[derive(Clone)]
pub struct Rc2 {
    keys: [u16; 64],
}

impl Rc2 {
    /// Create a cipher with the specified effective key length
    pub fn new_with_eff_key_len(key: &[u8], eff_key_len: usize) -> Self {
        Self {
            keys: Rc2::expand_key(key, eff_key_len),
        }
    }

    fn expand_key(key: &[u8], t1: usize) -> [u16; 64] {
        let key_len = key.len() as usize;

        let t8: usize = (t1 + 7) >> 3;

        let tm: usize = (255 % ((2u32).pow((8 + t1 - 8 * t8) as u32))) as usize;

        let mut key_buffer: [u8; 128] = [0; 128];
        key_buffer[..key_len].copy_from_slice(&key[..key_len]);

        for i in key_len..128 {
            let pos: u32 =
                (u32::from(key_buffer[i - 1]) + u32::from(key_buffer[i - key_len])) & 0xff;
            key_buffer[i] = PI_TABLE[pos as usize];
        }

        key_buffer[128 - t8] = PI_TABLE[(key_buffer[128 - t8] & tm as u8) as usize];

        for i in (0..128 - t8).rev() {
            let pos: usize = (key_buffer[i + 1] ^ key_buffer[i + t8]) as usize;
            key_buffer[i] = PI_TABLE[pos];
        }

        let mut result: [u16; 64] = [0; 64];
        for i in 0..64 {
            result[i] = (u16::from(key_buffer[2 * i + 1]) << 8) + u16::from(key_buffer[2 * i])
        }
        result
    }

    fn mix(&self, r: &mut [u16; 4], j: &mut usize) {
        r[0] = r[0]
            .wrapping_add(self.keys[*j])
            .wrapping_add(r[3] & r[2])
            .wrapping_add(!r[3] & r[1]);
        *j += 1;
        r[0] = (r[0] << 1) | (r[0] >> 15);

        r[1] = r[1]
            .wrapping_add(self.keys[*j])
            .wrapping_add(r[0] & r[3])
            .wrapping_add(!r[0] & r[2]);
        *j += 1;
        r[1] = (r[1] << 2) | (r[1] >> 14);

        r[2] = r[2]
            .wrapping_add(self.keys[*j])
            .wrapping_add(r[1] & r[0])
            .wrapping_add(!r[1] & r[3]);
        *j += 1;
        r[2] = (r[2] << 3) | (r[2] >> 13);

        r[3] = r[3]
            .wrapping_add(self.keys[*j])
            .wrapping_add(r[2] & r[1])
            .wrapping_add(!r[2] & r[0]);
        *j += 1;
        r[3] = (r[3] << 5) | (r[3] >> 11);
    }

    fn mash(&self, r: &mut [u16; 4]) {
        r[0] = r[0].wrapping_add(self.keys[(r[3] & 63) as usize]);
        r[1] = r[1].wrapping_add(self.keys[(r[0] & 63) as usize]);
        r[2] = r[2].wrapping_add(self.keys[(r[1] & 63) as usize]);
        r[3] = r[3].wrapping_add(self.keys[(r[2] & 63) as usize]);
    }

    fn reverse_mix(&self, r: &mut [u16; 4], j: &mut usize) {
        r[3] = (r[3] << 11) | (r[3] >> 5);
        r[3] = r[3]
            .wrapping_sub(self.keys[*j])
            .wrapping_sub(r[2] & r[1])
            .wrapping_sub(!r[2] & r[0]);
        *j -= 1;

        r[2] = (r[2] << 13) | (r[2] >> 3);
        r[2] = r[2]
            .wrapping_sub(self.keys[*j])
            .wrapping_sub(r[1] & r[0])
            .wrapping_sub(!r[1] & r[3]);
        *j -= 1;

        r[1] = (r[1] << 14) | (r[1] >> 2);
        r[1] = r[1]
            .wrapping_sub(self.keys[*j])
            .wrapping_sub(r[0] & r[3])
            .wrapping_sub(!r[0] & r[2]);
        *j -= 1;

        r[0] = (r[0] << 15) | (r[0] >> 1);
        r[0] = r[0]
            .wrapping_sub(self.keys[*j])
            .wrapping_sub(r[3] & r[2])
            .wrapping_sub(!r[3] & r[1]);
        *j = j.wrapping_sub(1);
    }

    fn reverse_mash(&self, r: &mut [u16; 4]) {
        r[3] = r[3].wrapping_sub(self.keys[(r[2] & 63) as usize]);
        r[2] = r[2].wrapping_sub(self.keys[(r[1] & 63) as usize]);
        r[1] = r[1].wrapping_sub(self.keys[(r[0] & 63) as usize]);
        r[0] = r[0].wrapping_sub(self.keys[(r[3] & 63) as usize]);
    }
}

impl BlockCipher for Rc2 {}

impl KeySizeUser for Rc2 {
    type KeySize = U32;
}

impl KeyInit for Rc2 {
    fn new(key: &Key<Self>) -> Self {
        Self::new_from_slice(key).unwrap()
    }

    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        if key.is_empty() || key.len() > 128 {
            Err(InvalidLength)
        } else {
            Ok(Self::new_with_eff_key_len(key, key.len() * 8))
        }
    }
}

impl fmt::Debug for Rc2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Rc2 { ... }")
    }
}

impl AlgorithmName for Rc2 {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Rc2")
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl Drop for Rc2 {
    fn drop(&mut self) {
        self.keys.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl ZeroizeOnDrop for Rc2 {}

cipher::impl_simple_block_encdec!(
    Rc2, U8, cipher, block,
    encrypt: {
        let b = block.get_in();
        let mut b = [
            u16::from_le_bytes(b[0..2].try_into().unwrap()),
            u16::from_le_bytes(b[2..4].try_into().unwrap()),
            u16::from_le_bytes(b[4..6].try_into().unwrap()),
            u16::from_le_bytes(b[6..8].try_into().unwrap()),
        ];

        let mut j = 0;

        for i in 0..16 {
            cipher.mix(&mut b, &mut j);
            if i == 4 || i == 10 {
                cipher.mash(&mut b);
            }
        }

        let block = block.get_out();
        block[0..2].copy_from_slice(&b[0].to_le_bytes());
        block[2..4].copy_from_slice(&b[1].to_le_bytes());
        block[4..6].copy_from_slice(&b[2].to_le_bytes());
        block[6..8].copy_from_slice(&b[3].to_le_bytes());
    }
    decrypt: {
        let b = block.get_in();
        let mut b = [
            u16::from_le_bytes(b[0..2].try_into().unwrap()),
            u16::from_le_bytes(b[2..4].try_into().unwrap()),
            u16::from_le_bytes(b[4..6].try_into().unwrap()),
            u16::from_le_bytes(b[6..8].try_into().unwrap()),
        ];

        let mut j = 63;

        for i in 0..16 {
            cipher.reverse_mix(&mut b, &mut j);
            if i == 4 || i == 10 {
                cipher.reverse_mash(&mut b);
            }
        }

        let block = block.get_out();
        block[0..2].copy_from_slice(&b[0].to_le_bytes());
        block[2..4].copy_from_slice(&b[1].to_le_bytes());
        block[4..6].copy_from_slice(&b[2].to_le_bytes());
        block[6..8].copy_from_slice(&b[3].to_le_bytes());
    }
);
