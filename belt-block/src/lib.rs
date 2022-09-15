//! Pure Rust implementation of the [BelT] block cipher.
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate implements only the low-level block cipher function, and is intended
//! for use for implementing higher-level constructions *only*. It is NOT
//! intended for direct use in applications.
//!
//! USE AT YOUR OWN RISK!
//!
//! [BelT]: https://ru.wikipedia.org/wiki/BelT

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]
#![forbid(unsafe_code)]

use crate::consts::{H13, H21, H29, H5};
pub use cipher;
use cipher::consts::{U16, U32};
use cipher::{inout::InOut, AlgorithmName, Block, BlockCipher, Key, KeyInit, KeySizeUser};
use core::{fmt, mem::swap, num::Wrapping};

mod consts;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

macro_rules! g {
    ($($name:ident: ($a:expr, $b:expr, $c:expr, $d:expr)),+) => {
        $(
            #[inline]
            fn $name(Wrapping(u): Wrapping<u32>) -> Wrapping<u32> {
                Wrapping($a[((u >> 24) & 0xFF) as usize]
                    ^ $b[((u >> 16) & 0xFF) as usize]
                    ^ $c[((u >> 8) & 0xFF) as usize]
                    ^ $d[(u & 0xFF) as usize])
            }
        )+
    }
}

g!(
    g5: (H29, H21, H13, H5),
    g13: (H5, H29, H21, H13),
    g21: (H13, H5, H29, H21)
);

/// BelT block cipher.
#[derive(Clone)]
pub struct BeltBlock {
    key: [Wrapping<u32>; 8],
}

#[inline(always)]
fn get_u32(block: &[u8], i: usize) -> Wrapping<u32> {
    Wrapping(u32::from_le_bytes(block[4 * i..][..4].try_into().unwrap()))
}

#[inline(always)]
fn set_u32(val: Wrapping<u32>, block: &mut [u8], i: usize) {
    block[4 * i..][..4].copy_from_slice(&val.0.to_le_bytes());
}

#[inline(always)]
fn idx(i: usize, delta: usize) -> usize {
    (7 * i - delta - 1) % 8
}

impl BeltBlock {
    /// Encryption as described in section 6.1.3
    #[inline]
    fn encrypt(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let key = &self.key;
        let block_in = block.get_in();
        // Steps 1 and 4
        let mut a = get_u32(block_in, 0);
        let mut b = get_u32(block_in, 1);
        let mut c = get_u32(block_in, 2);
        let mut d = get_u32(block_in, 3);

        // Step 5
        for i in 1..9 {
            // 5.1) b <- b xor G5(a+K[7i-6])
            b ^= g5(a + key[idx(i, 6)]);
            // 5.2) c <- c xor G21(a+K[7i-5])
            c ^= g21(d + key[idx(i, 5)]);
            // 5.3) a <- a - G13(a+K[7i-4])
            a -= g13(b + key[idx(i, 4)]);
            // 5.4) e <- G21(b+c+K[7i-3])+<i>_32
            let e = g21(b + c + key[idx(i, 3)]) ^ Wrapping(i as u32);
            // 5.5) b <- b+e
            b += e;
            // 5.6) c <- c-e
            c -= e;
            // 5.7) d <- d xor G13(c+K[7i-2])
            d += g13(c + key[idx(i, 2)]);
            // 5.8) b <- b xor G21(a + K[7i-1])
            b ^= g21(a + key[idx(i, 1)]);
            // 5.9) c <- c xor G5(d+K[7i])
            c ^= g5(d + key[idx(i, 0)]);
            // 5.10-5.12)
            swap(&mut a, &mut b);
            swap(&mut c, &mut d);
            swap(&mut b, &mut c);
        }

        let block_out = block.get_out();
        // Step 6
        set_u32(b, block_out, 0);
        set_u32(d, block_out, 1);
        set_u32(a, block_out, 2);
        set_u32(c, block_out, 3);
    }

    /// Decryption as described in section 6.1.4
    #[inline]
    fn decrypt(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let key = &self.key;
        let block_in = block.get_in();
        // Steps 1 and 4
        let mut a = get_u32(block_in, 0);
        let mut b = get_u32(block_in, 1);
        let mut c = get_u32(block_in, 2);
        let mut d = get_u32(block_in, 3);

        // Step 5
        for i in (1..9).rev() {
            // 5.1) b <- b xor G5(a+K[7i])
            b ^= g5(a + key[idx(i, 0)]);
            // 5.2) c <- c xor G21(a+K[7i-1])
            c ^= g21(d + key[idx(i, 1)]);
            // 5.3) a <- a - G13(a+K[7i-2])
            a -= g13(b + key[idx(i, 2)]);
            // 5.4) e <- G21(b+c+K[7i-3])+<i>_32
            let e = g21(b + c + key[idx(i, 3)]) ^ Wrapping(i as u32);
            // 5.5) b <- b+e
            b += e;
            // 5.6) c <- c-e
            c -= e;
            // 5.7) d <- d xor G13(c+K[7i-4])
            d += g13(c + key[idx(i, 4)]);
            // 5.8) b <- b xor G21(a + K[7i-5])
            b ^= g21(a + key[idx(i, 5)]);
            // 5.9) c <- c xor G5(d+K[7i-6])
            c ^= g5(d + key[idx(i, 6)]);

            // 5.10-5.12)
            swap(&mut a, &mut b);
            swap(&mut c, &mut d);
            swap(&mut a, &mut d);
        }

        let block_out = block.get_out();
        // Step 6
        set_u32(c, block_out, 0);
        set_u32(a, block_out, 1);
        set_u32(d, block_out, 2);
        set_u32(b, block_out, 3);
    }
}

impl BlockCipher for BeltBlock {}

impl KeySizeUser for BeltBlock {
    type KeySize = U32;
}

impl KeyInit for BeltBlock {
    fn new(key: &Key<Self>) -> Self {
        Self {
            key: [
                get_u32(key, 0),
                get_u32(key, 1),
                get_u32(key, 2),
                get_u32(key, 3),
                get_u32(key, 4),
                get_u32(key, 5),
                get_u32(key, 6),
                get_u32(key, 7),
            ],
        }
    }
}

impl AlgorithmName for BeltBlock {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BeltBlock")
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl Drop for BeltBlock {
    fn drop(&mut self) {
        for val in self.key.iter_mut() {
            val.0.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl ZeroizeOnDrop for BeltBlock {}

cipher::impl_simple_block_encdec!(
    BeltBlock, U16, cipher, block,
    encrypt: {
        cipher.encrypt(block);
    }
    decrypt: {
        cipher.decrypt(block);
    }
);
