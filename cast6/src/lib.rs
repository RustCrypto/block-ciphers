//! Pure Rust implementation of the [CAST6] block cipher ([RFC 2612]).
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
//! use cast6::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
//! use cast6::Cast6;
//!
//! let key = Array::from([0u8; 32]);
//! let mut block = Array::from([0u8; 16]);
//! // Initialize cipher
//! let cipher = Cast6::new(&key);
//!
//! let block_copy = block.clone();
//! // Encrypt block in-place
//! cipher.encrypt_block(&mut block);
//! // And decrypt it back
//! cipher.decrypt_block(&mut block);
//! assert_eq!(block, block_copy);
//! ```
//!
//! [CAST6]: https://en.wikipedia.org/wiki/CAST-256
//! [RFC 2612]: https://tools.ietf.org/html/rfc2612

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

pub use cipher;

mod consts;

use cipher::{
    AlgorithmName, Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, InOut,
    InvalidLength, Key, KeyInit, KeySizeUser, ParBlocksSizeUser,
    consts::{U1, U16, U32},
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

use consts::{S1, S2, S3, S4, TM, TR};

/// The CAST6 block cipher.
#[derive(Clone)]
pub struct Cast6 {
    masking: [[u32; 4]; 12],
    rotate: [[u8; 4]; 12],
}

impl Cast6 {
    /// Implements the key schedule according to RFC 2612 2.4.
    /// https://tools.ietf.org/html/rfc2612#section-2.4
    fn key_schedule(&mut self, key: &[u8; 32]) {
        let mut kappa = to_u32s(key);
        for i in 0..12 {
            let m_idx = 16 * i;
            let r_idx = 16 * (i % 2);

            let m = &TM[m_idx..][..8];
            let r = &TR[r_idx..][..8];
            forward_octave(&mut kappa, m, r);

            let m = &TM[m_idx + 8..][..8];
            let r = &TR[r_idx + 8..][..8];
            forward_octave(&mut kappa, m, r);

            let [a, b, c, d, e, f, g, h] = kappa;
            self.masking[i] = [h, f, d, b];

            self.rotate[i][0] = (a & 0x1f) as u8;
            self.rotate[i][1] = (c & 0x1f) as u8;
            self.rotate[i][2] = (e & 0x1f) as u8;
            self.rotate[i][3] = (g & 0x1f) as u8;
        }
    }
}

macro_rules! f1 {
    ($D:expr, $m:expr, $r:expr) => {{
        let i = ($m.wrapping_add($D)).rotate_left(u32::from($r));
        (S1[(i >> 24) as usize] ^ S2[((i >> 16) & 0xff) as usize])
            .wrapping_sub(S3[((i >> 8) & 0xff) as usize])
            .wrapping_add(S4[(i & 0xff) as usize])
    }};
}

macro_rules! f2 {
    ($D:expr, $m:expr, $r:expr) => {{
        let i = ($m ^ $D).rotate_left(u32::from($r));
        S1[(i >> 24) as usize]
            .wrapping_sub(S2[((i >> 16) & 0xff) as usize])
            .wrapping_add(S3[((i >> 8) & 0xff) as usize])
            ^ S4[(i & 0xff) as usize]
    }};
}

macro_rules! f3 {
    ($D:expr, $m:expr, $r:expr) => {{
        let i = ($m.wrapping_sub($D)).rotate_left(u32::from($r));
        (S1[(i >> 24) as usize].wrapping_add(S2[((i >> 16) & 0xff) as usize])
            ^ S3[((i >> 8) & 0xff) as usize])
            .wrapping_sub(S4[(i & 0xff) as usize])
    }};
}

#[inline]
fn forward_quad(beta: &mut [u32; 4], m: &[u32; 4], r: &[u8; 4]) {
    // Let "BETA <- Qi(BETA)" be short-hand notation for the following:
    //     C = C ^ f1(D, Kr0_(i), Km0_(i))
    //     B = B ^ f2(C, Kr1_(i), Km1_(i))
    //     A = A ^ f3(B, Kr2_(i), Km2_(i))
    //     D = D ^ f1(A, Kr3_(i), Km3_(i))

    let [a, b, c, d] = beta;
    *c ^= f1!(*d, m[0], r[0]);
    *b ^= f2!(*c, m[1], r[1]);
    *a ^= f3!(*b, m[2], r[2]);
    *d ^= f1!(*a, m[3], r[3]);
}

#[inline]
fn reverse_quad(beta: &mut [u32; 4], m: &[u32; 4], r: &[u8; 4]) {
    // Let "BETA <- QBARi(BETA)" be short-hand notation for the
    // following:
    //     D = D ^ f1(A, Kr3_(i), Km3_(i))
    //     A = A ^ f3(B, Kr2_(i), Km2_(i))
    //     B = B ^ f2(C, Kr1_(i), Km1_(i))
    //     C = C ^ f1(D, Kr0_(i), Km0_(i))

    let [a, b, c, d] = beta;
    *d ^= f1!(*a, m[3], r[3]);
    *a ^= f3!(*b, m[2], r[2]);
    *b ^= f2!(*c, m[1], r[1]);
    *c ^= f1!(*d, m[0], r[0]);
}

#[inline]
fn forward_octave(kappa: &mut [u32; 8], m: &[u32], r: &[u8]) {
    // Let "KAPPA <- Wi(KAPPA)" be short-hand notation for the
    // following:
    //     G = G ^ f1(H, Tr0_(i), Tm0_(i))
    //     F = F ^ f2(G, Tr1_(i), Tm1_(i))
    //     E = E ^ f3(F, Tr2_(i), Tm2_(i))
    //     D = D ^ f1(E, Tr3_(i), Tm3_(i))
    //     C = C ^ f2(D, Tr4_(i), Tm4_(i))
    //     B = B ^ f3(C, Tr5_(i), Tm5_(i))
    //     A = A ^ f1(B, Tr6_(i), Tm6_(i))
    //     H = H ^ f2(A, Tr7_(i), Tm7_(i))

    let [a, b, c, d, e, f, g, h] = kappa;
    *g ^= f1!(*h, m[0], r[0]);
    *f ^= f2!(*g, m[1], r[1]);
    *e ^= f3!(*f, m[2], r[2]);
    *d ^= f1!(*e, m[3], r[3]);
    *c ^= f2!(*d, m[4], r[4]);
    *b ^= f3!(*c, m[5], r[5]);
    *a ^= f1!(*b, m[6], r[6]);
    *h ^= f2!(*a, m[7], r[7]);
}

impl KeySizeUser for Cast6 {
    type KeySize = U32;
}

impl KeyInit for Cast6 {
    fn new(key: &Key<Self>) -> Self {
        Self::new_from_slice(key).unwrap()
    }

    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        // Available key sizes are 128, 160, 192, 224, and 256 bits.
        if ![16, 20, 24, 28, 32].contains(&key.len()) {
            return Err(InvalidLength);
        }
        let mut cast6 = Self {
            masking: [[0u32; 4]; 12],
            rotate: [[0u8; 4]; 12],
        };

        // Pad keys that are less than 256 bits long.
        let mut padded_key = [0u8; 32];
        padded_key[..key.len()].copy_from_slice(key);
        cast6.key_schedule(&padded_key);
        Ok(cast6)
    }
}

impl BlockSizeUser for Cast6 {
    type BlockSize = U16;
}

impl ParBlocksSizeUser for Cast6 {
    type ParBlocksSize = U1;
}

impl BlockCipherEncrypt for Cast6 {
    #[inline]
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl BlockCipherEncBackend for Cast6 {
    #[inline]
    fn encrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let masking = &self.masking;
        let rotate = &self.rotate;

        // Let BETA = (ABCD) be a 128-bit block where A, B, C and D are each
        // 32 bits in length.
        // BETA = 128bits of plaintext.
        let mut beta = to_u32s(block.get_in());

        // for (i=0; i<6; i++)
        //     BETA <- Qi(BETA)
        forward_quad(&mut beta, &masking[0], &rotate[0]);
        forward_quad(&mut beta, &masking[1], &rotate[1]);
        forward_quad(&mut beta, &masking[2], &rotate[2]);
        forward_quad(&mut beta, &masking[3], &rotate[3]);
        forward_quad(&mut beta, &masking[4], &rotate[4]);
        forward_quad(&mut beta, &masking[5], &rotate[5]);

        // for (i=6; i<12; i++)
        //     BETA <- QBARi(BETA)
        reverse_quad(&mut beta, &masking[6], &rotate[6]);
        reverse_quad(&mut beta, &masking[7], &rotate[7]);
        reverse_quad(&mut beta, &masking[8], &rotate[8]);
        reverse_quad(&mut beta, &masking[9], &rotate[9]);
        reverse_quad(&mut beta, &masking[10], &rotate[10]);
        reverse_quad(&mut beta, &masking[11], &rotate[11]);

        // 128bits of ciphertext = BETA
        *block.get_out() = to_u8s::<16>(&beta).into();
    }
}

impl BlockCipherDecrypt for Cast6 {
    #[inline]
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl BlockCipherDecBackend for Cast6 {
    #[inline]
    fn decrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let masking = &self.masking;
        let rotate = &self.rotate;

        let mut beta = to_u32s(block.get_in());

        forward_quad(&mut beta, &masking[11], &rotate[11]);
        forward_quad(&mut beta, &masking[10], &rotate[10]);
        forward_quad(&mut beta, &masking[9], &rotate[9]);
        forward_quad(&mut beta, &masking[8], &rotate[8]);
        forward_quad(&mut beta, &masking[7], &rotate[7]);
        forward_quad(&mut beta, &masking[6], &rotate[6]);

        reverse_quad(&mut beta, &masking[5], &rotate[5]);
        reverse_quad(&mut beta, &masking[4], &rotate[4]);
        reverse_quad(&mut beta, &masking[3], &rotate[3]);
        reverse_quad(&mut beta, &masking[2], &rotate[2]);
        reverse_quad(&mut beta, &masking[1], &rotate[1]);
        reverse_quad(&mut beta, &masking[0], &rotate[0]);

        *block.get_out() = to_u8s::<16>(&beta).into();
    }
}

impl fmt::Debug for Cast6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Cast6 { ... }")
    }
}

impl AlgorithmName for Cast6 {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Cast6")
    }
}

impl Drop for Cast6 {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.masking.zeroize();
            self.rotate.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for Cast6 {}

fn to_u32s<const N: usize>(src: &[u8]) -> [u32; N] {
    assert_eq!(src.len(), 4 * N);
    let mut res = [0u32; N];
    for (chunk, dst) in src.chunks_exact(4).zip(res.iter_mut()) {
        *dst = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    res
}

fn to_u8s<const N: usize>(src: &[u32]) -> [u8; N] {
    assert_eq!(4 * src.len(), N);
    let mut res = [0u8; N];
    for (dst_chunk, src) in res.chunks_exact_mut(4).zip(src.iter()) {
        dst_chunk.copy_from_slice(&src.to_be_bytes());
    }
    res
}
