//! Pure Rust implementation of the [Threefish] block ciphers.
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate implements only the low-level block cipher function, and is intended
//! for use for implementing higher-level constructions *only*. It is NOT
//! intended for direct use in applications.
//!
//! USE AT YOUR OWN RISK!
//!
//! [Threefish]: https://en.wikipedia.org/wiki/Threefish

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "cipher")]
pub use cipher;

use core::fmt;

#[cfg(feature = "cipher")]
use cipher::{
    AlgorithmName, Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, InOut, Key,
    KeyInit, KeySizeUser, ParBlocksSizeUser,
    consts::{U1, U32, U64, U128},
};

mod consts;

use crate::consts::{C240, P256, P512, P1024, R256, R512, R1024};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

fn mix(r: u8, x: (u64, u64)) -> (u64, u64) {
    let y0 = x.0.wrapping_add(x.1);
    let y1 = x.1.rotate_left(r as u32) ^ y0;
    (y0, y1)
}

fn inv_mix(r: u8, y: (u64, u64)) -> (u64, u64) {
    let x1 = (y.0 ^ y.1).rotate_right(r as u32);
    let x0 = y.0.wrapping_sub(x1);
    (x0, x1)
}

macro_rules! impl_threefish(
    (
        $name:ident, $rounds:expr, $n_w:expr, $block_size:ty,
        $rot:expr, $perm:expr, $doc_name:expr
    ) => (
        #[doc=$doc_name]
        #[doc="block cipher."]
        #[derive(Clone)]
        pub struct $name {
            sk: [[u64; $n_w]; $rounds / 4 + 1]
        }

        impl $name {
            /// Create new block cipher instance with the given key and tweak.
            #[inline(always)]
            pub fn new_with_tweak(key: &[u8; $n_w*8], tweak: &[u8; 16]) -> $name {
                let mut k = [0u64; $n_w];
                for (kv, chunk) in k[..$n_w].iter_mut().zip(key.chunks_exact(8)) {
                    *kv = u64::from_le_bytes(chunk.try_into().unwrap());
                }
                let tweak = [
                    u64::from_le_bytes(tweak[..8].try_into().unwrap()),
                    u64::from_le_bytes(tweak[8..].try_into().unwrap()),
                ];
                Self::new_with_tweak_u64(&k, &tweak)
            }

            /// Create new block cipher instance with the given key and tweak
            /// represented in the form of array of `u64`s.
            #[inline(always)]
            pub fn new_with_tweak_u64(key: &[u64; $n_w], tweak: &[u64; 2]) -> $name {
                let mut k = [0u64; $n_w + 1];
                k[..$n_w].copy_from_slice(key);
                k[$n_w] = key.iter().fold(C240, core::ops::BitXor::bitxor);
                let t = [tweak[0], tweak[1], tweak[0] ^ tweak[1]];

                let mut sk = [[0u64; $n_w]; $rounds / 4 + 1];
                for s in 0..=($rounds / 4) {
                    for i in 0..$n_w {
                        sk[s][i] = k[(s + i) % ($n_w + 1)];
                        if i == $n_w - 3 {
                            sk[s][i] = sk[s][i].wrapping_add(t[s % 3]);
                        } else if i == $n_w - 2 {
                            sk[s][i] = sk[s][i].wrapping_add(t[(s + 1) % 3]);
                        } else if i == $n_w - 1 {
                            sk[s][i] = sk[s][i].wrapping_add(s as u64);
                        }
                    }
                }

                $name { sk }
            }

            /// Encrypt block in the form of array of `u64`s
            #[inline(always)]
            pub fn encrypt_block_u64(&self, block: &mut [u64; $n_w]) {
                for d in 0..$rounds {
                    let block_prev = block.clone();
                    for j in 0..($n_w / 2) {
                        let v = (block_prev[2 * j], block_prev[2 * j + 1]);
                        let e = if d % 4 == 0 {
                            let s0 = self.sk[d / 4][2 * j];
                            let s1 = self.sk[d / 4][2 * j + 1];
                            (v.0.wrapping_add(s0), v.1.wrapping_add(s1))
                        } else {
                            v
                        };
                        let r = $rot[d % 8][j];
                        let (f0, f1) = mix(r, e);
                        let (pi0, pi1) = ($perm[2 * j], $perm[2 * j + 1]);
                        block[pi0 as usize] = f0;
                        block[pi1 as usize] = f1;
                    }
                }

                for (b, s) in block.iter_mut().zip(&self.sk[$rounds / 4]) {
                    *b = b.wrapping_add(*s);
                }
            }

            /// Decrypt block in the form of array of `u64`s
            #[inline(always)]
            pub fn decrypt_block_u64(&self, block: &mut [u64; $n_w]) {
                for (b, s) in block.iter_mut().zip(&self.sk[$rounds / 4]) {
                    *b = b.wrapping_sub(*s);
                }

                for d in (0..$rounds).rev() {
                    let block_prev = block.clone();
                    for j in 0..($n_w / 2) {
                        let (pi0, pi1) = ($perm[2 * j], $perm[2 * j + 1]);
                        let f = (block_prev[pi0 as usize], block_prev[pi1 as usize]);
                        let r = $rot[d % 8][j];
                        let (e0, e1) = inv_mix(r, f);
                        if d % 4 == 0 {
                            let s0 = self.sk[d / 4][2 * j];
                            let s1 = self.sk[d / 4][2 * j + 1];
                            block[2 * j] = e0.wrapping_sub(s0);
                            block[2 * j + 1] = e1.wrapping_sub(s1);
                        } else {
                            block[2 * j] = e0;
                            block[2 * j + 1] = e1;
                        }
                    }
                }
            }
        }

        #[cfg(feature = "cipher")]
        impl KeySizeUser for $name {
            type KeySize = $block_size;
        }

        #[cfg(feature = "cipher")]
        impl KeyInit for $name {
            fn new(key: &Key<Self>) -> Self {
                let mut tmp_key = [0u8; $n_w*8];
                tmp_key.copy_from_slice(key);
                Self::new_with_tweak(&tmp_key, &Default::default())
            }
        }

        #[cfg(feature = "cipher")]
        impl BlockSizeUser for $name {
            type BlockSize = $block_size;
        }

        #[cfg(feature = "cipher")]
        impl ParBlocksSizeUser for $name {
            type ParBlocksSize = U1;
        }

        #[cfg(feature = "cipher")]
        impl BlockCipherEncrypt for $name {
            #[inline]
            fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
                f.call(self)
            }
        }

        #[cfg(feature = "cipher")]
        impl BlockCipherEncBackend for $name {
            #[inline]
            fn encrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
                let mut v = [0u64; $n_w];
                let b = block.get_in();
                for (vv, chunk) in v.iter_mut().zip(b.chunks_exact(8)) {
                    *vv = u64::from_le_bytes(chunk.try_into().unwrap());
                }

                self.encrypt_block_u64(&mut v);

                let block = block.get_out();
                for (chunk, vv) in block.chunks_exact_mut(8).zip(v.iter()) {
                    chunk.copy_from_slice(&vv.to_le_bytes());
                }
            }
        }

        #[cfg(feature = "cipher")]
        impl BlockCipherDecrypt for $name {
            #[inline]
            fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
                f.call(self)
            }
        }

        #[cfg(feature = "cipher")]
        impl BlockCipherDecBackend for $name {
            #[inline]
            fn decrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
                let mut v = [0u64; $n_w];
                let b = block.get_in();
                for (vv, chunk) in v.iter_mut().zip(b.chunks_exact(8)) {
                    *vv = u64::from_le_bytes(chunk.try_into().unwrap());
                }

                self.decrypt_block_u64(&mut v);

                let block = block.get_out();
                for (chunk, vv) in block.chunks_exact_mut(8).zip(v.iter()) {
                    chunk.copy_from_slice(&vv.to_le_bytes());
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }

        #[cfg(feature = "cipher")]
        impl AlgorithmName for $name {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($name))
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                #[cfg(all(feature = "zeroize"))]
                self.sk.zeroize();
            }
        }

        #[cfg(all(feature = "zeroize"))]
        impl ZeroizeOnDrop for $name {}
    )
);

impl_threefish!(Threefish256, 72, 4, U32, R256, P256, "Threefish-256");
impl_threefish!(Threefish512, 72, 8, U64, R512, P512, "Threefish-512");
impl_threefish!(Threefish1024, 80, 16, U128, R1024, P1024, "Threefish-1024");
