//! Pure Rust implementation of the [Twofish] block cipher.
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate implements only the low-level block cipher function, and is intended
//! for use for implementing higher-level constructions *only*. It is NOT
//! intended for direct use in applications.
//!
//! USE AT YOUR OWN RISK!
//!
//! [Twofish]: https://en.wikipedia.org/wiki/Twofish

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_root_url = "https://docs.rs/twofish/0.7.1"
)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]
#![allow(clippy::needless_range_loop, clippy::unreadable_literal)]

pub use cipher;

use cipher::{
    consts::{U16, U32},
    AlgorithmName, BlockCipher, InvalidLength, Key, KeyInit, KeySizeUser,
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

mod consts;
use crate::consts::{MDS_POLY, QBOX, QORD, RS, RS_POLY};

/// Twofish block cipher
#[derive(Clone)]
pub struct Twofish {
    s: [u8; 16],  // S-box key
    k: [u32; 40], // Subkeys
    start: usize,
}

fn gf_mult(mut a: u8, mut b: u8, p: u8) -> u8 {
    let mut result = 0;
    while a > 0 {
        if a & 1 == 1 {
            result ^= b;
        }
        a >>= 1;
        if b & 0x80 == 0x80 {
            b = (b << 1) ^ p;
        } else {
            b <<= 1;
        }
    }
    result
}

// q_i sbox
fn sbox(i: usize, x: u8) -> u8 {
    let (a0, b0) = (x >> 4 & 15, x & 15);
    let a1 = a0 ^ b0;
    let b1 = (a0 ^ ((b0 << 3) | (b0 >> 1)) ^ (a0 << 3)) & 15;
    let (a2, b2) = (QBOX[i][0][a1 as usize], QBOX[i][1][b1 as usize]);
    let a3 = a2 ^ b2;
    let b3 = (a2 ^ ((b2 << 3) | (b2 >> 1)) ^ (a2 << 3)) & 15;
    let (a4, b4) = (QBOX[i][2][a3 as usize], QBOX[i][3][b3 as usize]);
    (b4 << 4) + a4
}

fn mds_column_mult(x: u8, column: usize) -> u32 {
    let x5b = gf_mult(x, 0x5b, MDS_POLY);
    let xef = gf_mult(x, 0xef, MDS_POLY);

    let v = match column {
        0 => [x, x5b, xef, xef],
        1 => [xef, xef, x5b, x],
        2 => [x5b, xef, x, xef],
        3 => [x5b, x, xef, x5b],
        _ => unreachable!(),
    };
    u32::from_le_bytes(v)
}

fn mds_mult(y: [u8; 4]) -> u32 {
    let mut z = 0;
    for i in 0..4 {
        z ^= mds_column_mult(y[i], i);
    }
    z
}

fn rs_mult(m: &[u8], out: &mut [u8]) {
    for i in 0..4 {
        out[i] = 0;
        for j in 0..8 {
            out[i] ^= gf_mult(m[j], RS[i][j], RS_POLY);
        }
    }
}

#[allow(clippy::many_single_char_names)]
fn h(x: u32, m: &[u8], k: usize, offset: usize) -> u32 {
    let mut y = x.to_le_bytes();

    if k == 4 {
        y[0] = sbox(1, y[0]) ^ m[4 * (6 + offset)];
        y[1] = sbox(0, y[1]) ^ m[4 * (6 + offset) + 1];
        y[2] = sbox(0, y[2]) ^ m[4 * (6 + offset) + 2];
        y[3] = sbox(1, y[3]) ^ m[4 * (6 + offset) + 3];
    }

    if k >= 3 {
        y[0] = sbox(1, y[0]) ^ m[4 * (4 + offset)];
        y[1] = sbox(1, y[1]) ^ m[4 * (4 + offset) + 1];
        y[2] = sbox(0, y[2]) ^ m[4 * (4 + offset) + 2];
        y[3] = sbox(0, y[3]) ^ m[4 * (4 + offset) + 3];
    }

    let a = 4 * (2 + offset);
    let b = 4 * offset;
    y[0] = sbox(1, sbox(0, sbox(0, y[0]) ^ m[a]) ^ m[b]);
    y[1] = sbox(0, sbox(0, sbox(1, y[1]) ^ m[a + 1]) ^ m[b + 1]);
    y[2] = sbox(1, sbox(1, sbox(0, y[2]) ^ m[a + 2]) ^ m[b + 2]);
    y[3] = sbox(0, sbox(1, sbox(1, y[3]) ^ m[a + 3]) ^ m[b + 3]);

    mds_mult(y)
}

impl Twofish {
    fn g_func(&self, x: u32) -> u32 {
        let mut result: u32 = 0;
        for y in 0..4 {
            let mut g = sbox(QORD[y][self.start], (x >> (8 * y)) as u8);

            for z in self.start + 1..5 {
                g ^= self.s[4 * (z - self.start - 1) + y];
                g = sbox(QORD[y][z], g);
            }

            result ^= mds_column_mult(g, y);
        }
        result
    }

    fn key_schedule(&mut self, key: &[u8]) {
        let k = key.len() / 8;

        let rho: u32 = 0x1010101;

        for x in 0..20 {
            let a = h(rho * (2 * x), key, k, 0);
            let b = h(rho * (2 * x + 1), key, k, 1).rotate_left(8);
            let v = a.wrapping_add(b);
            self.k[(2 * x) as usize] = v;
            self.k[(2 * x + 1) as usize] = (v.wrapping_add(b)).rotate_left(9);
        }
        self.start = match k {
            4 => 0,
            3 => 1,
            2 => 2,
            _ => unreachable!(),
        };

        // Compute S_i.
        for i in 0..k {
            rs_mult(&key[i * 8..i * 8 + 8], &mut self.s[i * 4..(i + 1) * 4]);
        }
    }
}

impl BlockCipher for Twofish {}

impl KeySizeUser for Twofish {
    type KeySize = U32;
}

impl KeyInit for Twofish {
    #[inline]
    fn new(key: &Key<Self>) -> Self {
        Self::new_from_slice(key).unwrap()
    }

    #[inline]
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        let n = key.len();
        if n != 16 && n != 24 && n != 32 {
            return Err(InvalidLength);
        }
        let mut twofish = Self {
            s: [0u8; 16],
            k: [0u32; 40],
            start: 0,
        };
        twofish.key_schedule(key);
        Ok(twofish)
    }
}

impl fmt::Debug for Twofish {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Twofish { ... }")
    }
}

impl AlgorithmName for Twofish {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Twofish")
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl Drop for Twofish {
    fn drop(&mut self) {
        self.s.zeroize();
        self.k.zeroize();
        self.start.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl ZeroizeOnDrop for Twofish {}

cipher::impl_simple_block_encdec!(
    Twofish, U16, cipher, block,
    encrypt: {
        let b = block.get_in();
        let mut p = [
            u32::from_le_bytes(b[0..4].try_into().unwrap()),
            u32::from_le_bytes(b[4..8].try_into().unwrap()),
            u32::from_le_bytes(b[8..12].try_into().unwrap()),
            u32::from_le_bytes(b[12..16].try_into().unwrap()),
        ];

        // Input whitening
        for i in 0..4 {
            p[i] ^= cipher.k[i];
        }

        for r in 0..8 {
            let k = 4 * r + 8;

            let t1 = cipher.g_func(p[1].rotate_left(8));
            let t0 = cipher.g_func(p[0]).wrapping_add(t1);
            p[2] = (p[2] ^ (t0.wrapping_add(cipher.k[k]))).rotate_right(1);
            let t2 = t1.wrapping_add(t0).wrapping_add(cipher.k[k + 1]);
            p[3] = p[3].rotate_left(1) ^ t2;

            let t1 = cipher.g_func(p[3].rotate_left(8));
            let t0 = cipher.g_func(p[2]).wrapping_add(t1);
            p[0] = (p[0] ^ (t0.wrapping_add(cipher.k[k + 2]))).rotate_right(1);
            let t2 = t1.wrapping_add(t0).wrapping_add(cipher.k[k + 3]);
            p[1] = (p[1].rotate_left(1)) ^ t2;
        }

        // Undo last swap and output whitening
        p[2] ^= cipher.k[4];
        p[3] ^= cipher.k[5];
        p[0] ^= cipher.k[6];
        p[1] ^= cipher.k[7];

        let block = block.get_out();
        block[0..4].copy_from_slice(&p[2].to_le_bytes());
        block[4..8].copy_from_slice(&p[3].to_le_bytes());
        block[8..12].copy_from_slice(&p[0].to_le_bytes());
        block[12..16].copy_from_slice(&p[1].to_le_bytes());
    }
    decrypt: {
        let b = block.get_in();
        let mut c = [
            u32::from_le_bytes(b[8..12].try_into().unwrap()) ^ cipher.k[6],
            u32::from_le_bytes(b[12..16].try_into().unwrap()) ^ cipher.k[7],
            u32::from_le_bytes(b[0..4].try_into().unwrap()) ^ cipher.k[4],
            u32::from_le_bytes(b[4..8].try_into().unwrap()) ^ cipher.k[5],
        ];

        for r in (0..8).rev() {
            let k = 4 * r + 8;

            let t1 = cipher.g_func(c[3].rotate_left(8));
            let t0 = cipher.g_func(c[2]).wrapping_add(t1);
            c[0] = c[0].rotate_left(1) ^ (t0.wrapping_add(cipher.k[k + 2]));
            let t2 = t1.wrapping_add(t0).wrapping_add(cipher.k[k + 3]);
            c[1] = (c[1] ^ t2).rotate_right(1);

            let t1 = cipher.g_func(c[1].rotate_left(8));
            let t0 = cipher.g_func(c[0]).wrapping_add(t1);
            c[2] = c[2].rotate_left(1) ^ (t0.wrapping_add(cipher.k[k]));
            let t2 = t1.wrapping_add(t0).wrapping_add(cipher.k[k + 1]);
            c[3] = (c[3] ^ t2).rotate_right(1);
        }

        for i in 0..4 {
            c[i] ^= cipher.k[i];
        }

        let block = block.get_out();
        block[0..4].copy_from_slice(&c[0].to_le_bytes());
        block[4..8].copy_from_slice(&c[1].to_le_bytes());
        block[8..12].copy_from_slice(&c[2].to_le_bytes());
        block[12..16].copy_from_slice(&c[3].to_le_bytes());
    }
);

#[cfg(test)]
mod tests;
