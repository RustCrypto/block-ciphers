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
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_root_url = "https://docs.rs/threefish/0.5.1"
)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

pub use cipher;

mod consts;

use crate::consts::{C240, P1024, P256, P512, R1024, R256, R512};
use cipher::{
    consts::{U128, U32, U64},
    AlgorithmName, BlockCipher, Key, KeyInit, KeySizeUser,
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

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
            pub fn new_with_tweak(key: &[u8; $n_w*8], tweak: &[u8; 16]) -> $name {
                let mut k = [0u64; $n_w + 1];
                for (kv, chunk) in k[..$n_w].iter_mut().zip(key.chunks_exact(8)) {
                    *kv = u64::from_le_bytes(chunk.try_into().unwrap());
                }
                k[$n_w] = k[..$n_w].iter().fold(C240, core::ops::BitXor::bitxor);

                let t0 = u64::from_le_bytes(tweak[..8].try_into().unwrap());
                let t1 = u64::from_le_bytes(tweak[8..].try_into().unwrap());
                let t = [t0, t1, t0 ^ t1];

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
        }

        impl BlockCipher for $name {}

        impl KeySizeUser for $name {
            type KeySize = $block_size;
        }

        impl KeyInit for $name {
            fn new(key: &Key<Self>) -> Self {
                let mut tmp_key = [0u8; $n_w*8];
                tmp_key.copy_from_slice(key);
                Self::new_with_tweak(&tmp_key, &Default::default())
            }
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
                self.sk.zeroize();
            }
        }

        #[cfg(feature = "zeroize")]
        #[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
        impl ZeroizeOnDrop for $name {}

        cipher::impl_simple_block_encdec!(
            $name, $block_size, cipher, block,
            encrypt: {
                let mut v = [0u64; $n_w];
                let b = block.get_in();
                for (vv, chunk) in v.iter_mut().zip(b.chunks_exact(8)) {
                    *vv = u64::from_le_bytes(chunk.try_into().unwrap());
                }

                for d in 0..$rounds {
                    let v_tmp = v.clone();
                    for j in 0..($n_w / 2) {
                        let (v0, v1) = (v_tmp[2 * j], v_tmp[2 * j + 1]);
                        let (e0, e1) =
                            if d % 4 == 0 {
                                (v0.wrapping_add(cipher.sk[d / 4][2 * j]),
                                 v1.wrapping_add(cipher.sk[d / 4][2 * j + 1]))
                            } else {
                                (v0, v1)
                            };
                        let r = $rot[d % 8][j];
                        let (f0, f1) = mix(r, (e0, e1));
                        let (pi0, pi1) =
                            ($perm[2 * j], $perm[2 * j + 1]);
                        v[pi0 as usize] = f0;
                        v[pi1 as usize] = f1;
                    }
                }

                for i in 0..$n_w {
                    v[i] = v[i].wrapping_add(cipher.sk[$rounds / 4][i]);
                }

                let block = block.get_out();
                for (chunk, vv) in block.chunks_exact_mut(8).zip(v.iter()) {
                    chunk.copy_from_slice(&vv.to_le_bytes());
                }
            }
            decrypt: {
                let mut v = [0u64; $n_w];
                let b = block.get_in();
                for (vv, chunk) in v.iter_mut().zip(b.chunks_exact(8)) {
                    *vv = u64::from_le_bytes(chunk.try_into().unwrap());
                }

                for i in 0..$n_w {
                    v[i] = v[i].wrapping_sub(cipher.sk[$rounds / 4][i]);
                }

                for d in (0..$rounds).rev() {
                    let v_tmp = v.clone();
                    for j in 0..($n_w / 2) {
                        let (inv_pi0, inv_pi1) =
                            ($perm[2 * j] as usize, $perm[2 * j + 1] as usize);
                        let (f0, f1) = (v_tmp[inv_pi0], v_tmp[inv_pi1]);
                        let r = $rot[d % 8][j];
                        let (e0, e1) = inv_mix(r, (f0, f1));
                        let (v0, v1) =
                            if d % 4 == 0 {
                                (e0.wrapping_sub(cipher.sk[d / 4][2 * j]),
                                 e1.wrapping_sub(cipher.sk[d / 4][2 * j + 1]))
                             } else {
                                 (e0, e1)
                             };
                        v[2 * j] = v0;
                        v[2 * j + 1] = v1;
                    }
                }

                let block = block.get_out();
                for (chunk, vv) in block.chunks_exact_mut(8).zip(v.iter()) {
                    chunk.copy_from_slice(&vv.to_le_bytes());
                }
            }
        );
    )
);

impl_threefish!(Threefish256, 72, 4, U32, R256, P256, "Threefish-256");
impl_threefish!(Threefish512, 72, 8, U64, R512, P512, "Threefish-512");
impl_threefish!(Threefish1024, 80, 16, U128, R1024, P1024, "Threefish-1024");
