//! Pure Rust implementation of the [BelT] block cipher specified in
//! [STB 34.101.31-2020].
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
//! [STB 34.101.31-2020]: http://apmi.bsu.by/assets/files/std/belt-spec371.pdf

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]
#![forbid(unsafe_code)]

#[cfg(feature = "cipher")]
pub use cipher;

use crate::consts::{H13, H21, H29, H5};
use core::{mem::swap, num::Wrapping};

#[cfg(feature = "cipher")]
mod cipher_impl;
mod consts;

#[cfg(feature = "cipher")]
pub use cipher_impl::BeltBlock;

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

#[inline(always)]
fn key_idx(key: &[u32; 8], i: usize, delta: usize) -> Wrapping<u32> {
    Wrapping(key[(7 * i - delta - 1) % 8])
}

/// Raw BelT block encryption function used for implementation of
/// higher-level algorithms.
#[inline(always)]
pub fn belt_block_raw(x: [u32; 4], key: &[u32; 8]) -> [u32; 4] {
    let mut a = Wrapping(x[0]);
    let mut b = Wrapping(x[1]);
    let mut c = Wrapping(x[2]);
    let mut d = Wrapping(x[3]);

    // Step 5
    for i in 1..9 {
        // 5.1) b ← b ⊕ G₅(a ⊞ k[7i-6])
        b ^= g5(a + key_idx(key, i, 6));
        // 5.2) c ← c ⊕ G₂₁(d ⊞ k[7i-5])
        c ^= g21(d + key_idx(key, i, 5));
        // 5.3) a ← a ⊟ G₁₃(b ⊞ k[7i-4])
        a -= g13(b + key_idx(key, i, 4));
        // 5.4) e ← G₂₁(b ⊞ c ⊞ k[7i-3]) ⊕ ⟨i⟩₃₂ ;
        let e = g21(b + c + key_idx(key, i, 3)) ^ Wrapping(i as u32);
        // 5.5) b ← b ⊞ e
        b += e;
        // 5.6) c ← c ⊟ e
        c -= e;
        // 5.7) d ← d ⊞ G₁₃(c ⊞ 𝑘[7i-2])
        d += g13(c + key_idx(key, i, 2));
        // 5.8) b ← b ⊕ G₂₁(a ⊞ 𝑘[(7i-1])
        b ^= g21(a + key_idx(key, i, 1));
        // 5.9) c ← c ⊕ G₅(d ⊞ 𝑘[7i])
        c ^= g5(d + key_idx(key, i, 0));
        // 5.10) a ↔ b
        swap(&mut a, &mut b);
        // 5.11) c ↔ d
        swap(&mut c, &mut d);
        // 5.12) b ↔ c
        swap(&mut b, &mut c);
    }

    // Step 6
    [b.0, d.0, a.0, c.0]
}
