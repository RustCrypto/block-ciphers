//! Pure Rust implementation of the [Belt-block][belt-block]
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate implements only the low-level block cipher function, and is intended
//! for use for implementing higher-level constructions *only*. It is NOT
//! intended for direct use in applications.
//!
//! USE AT YOUR OWN RISK!
//!
//! [belt-block]: https://ru.wikipedia.org/wiki/BelT

#![no_std]

use crate::consts::{H13, H21, H29, H5};
pub use cipher;
use cipher::consts::{U16, U32};
use cipher::{AlgorithmName, BlockCipher, Key, KeyInit, KeySizeUser};
use core::fmt;
use core::ptr::{slice_from_raw_parts, slice_from_raw_parts_mut};

mod consts;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

macro_rules! g {
    ($($name:ident: ($a:expr, $b:expr, $c:expr, $d:expr)),+) => {
        $(
            #[inline]
            fn $name(u: u32) -> u32 {
                $a[((u >> 24) & 0xFF) as usize]
                    ^ $b[((u >> 16) & 0xFF) as usize]
                    ^ $c[((u >> 8) & 0xFF) as usize]
                    ^ $d[(u & 0xFF) as usize]
            }
        )+
    }
}

g!(
    g5: (H29, H21, H13, H5),
    g13: (H5, H29, H21, H13),
    g21: (H13, H5, H29, H21)
);

#[derive(Clone)]
pub struct BeltBlock {
    pub(crate) key: [u32; 8],
}

#[inline]
#[allow(clippy::many_single_char_names)]
/// Tact substitution, stands for 2.1-2.9 steps 6.1.3 algorithm (Block encryption) STB 34.101.31-2011
fn tact_enc(i: u32, a: u32, b: u32, c: u32, d: u32, data: &mut [u32], key: &[u32]) {
    // 2.1) b <- b xor G5(a+K[7i-6])
    data[b as usize] ^= g5(data[a as usize].wrapping_add(key[(7 * i as usize - 6 - 1) % 8]));
    // 2.2) c <- c xor G21(a+K[7i-5])
    data[c as usize] ^= g21(data[d as usize].wrapping_add(key[(7 * i as usize - 5 - 1) % 8]));
    // 2.3) a <- a - G13(a+K[7i-4])
    data[a as usize] = data[a as usize].wrapping_sub(g13(
        data[b as usize].wrapping_add(key[(7 * i as usize - 4 - 1) % 8])
    ));
    // 2.4) e <- G21(b+c+K[7i-3])+<i>_32
    let e = g21(data[b as usize]
        .wrapping_add(data[c as usize])
        .wrapping_add(key[(7 * i as usize - 3 - 1) % 8]))
        ^ i;
    // 2.5) b <- b+e
    data[b as usize] = data[b as usize].wrapping_add(e);
    // 2.6) c <- c-e
    data[c as usize] = data[c as usize].wrapping_sub(e);
    // 2.7) d <- d xor G13(c+K[7i-2])
    data[d as usize] = data[d as usize].wrapping_add(g13(
        data[c as usize].wrapping_add(key[(7 * i as usize - 2 - 1) % 8])
    ));
    // 2.8) b <- b xor G21(a + K[7i-1])
    data[b as usize] ^= g21(data[a as usize].wrapping_add(key[(7 * i as usize - 1 - 1) % 8]));
    // 2.9) c <- c xor G5(d+K[7i])
    data[c as usize] ^= g5(data[d as usize].wrapping_add(key[(7 * i as usize - 1) % 8]));
}

#[inline]
#[allow(clippy::many_single_char_names)]
/// Tact substitution, stands for 2.1-2.9 steps 6.1.4 algorithm (Block decryption) STB 34.101.31-2011
fn tact_dec(i: u32, a: u32, b: u32, c: u32, d: u32, data: &mut [u32], key: &[u32]) {
    // 2.1) b <- b xor G5(a+K[7i])
    data[b as usize] ^= g5(data[a as usize].wrapping_add(key[(7 * i as usize - 1) % 8]));
    // 2.2) c <- c xor G21(a+K[7i-1])
    data[c as usize] ^= g21(data[d as usize].wrapping_add(key[(7 * i as usize - 1 - 1) % 8]));
    // 2.3) a <- a - G13(a+K[7i-2])
    data[a as usize] = data[a as usize].wrapping_sub(g13(
        data[b as usize].wrapping_add(key[(7 * i as usize - 2 - 1) % 8])
    ));
    // 2.4) e <- G21(b+c+K[7i-3])+<i>_32
    let e = g21(data[b as usize]
        .wrapping_add(data[c as usize])
        .wrapping_add(key[(7 * i as usize - 3 - 1) % 8]))
        ^ i;
    // 2.5) b <- b+e
    data[b as usize] = data[b as usize].wrapping_add(e);
    // 2.6) c <- c-e
    data[c as usize] = data[c as usize].wrapping_sub(e);
    // 2.7) d <- d xor G13(c+K[7i-4])
    data[d as usize] = data[d as usize].wrapping_add(g13(
        data[c as usize].wrapping_add(key[(7 * i as usize - 4 - 1) % 8])
    ));
    // 2.8) b <- b xor G21(a + K[7i-5])
    data[b as usize] ^= g21(data[a as usize].wrapping_add(key[(7 * i as usize - 5 - 1) % 8]));
    // 2.9) c <- c xor G5(d+K[7i-6])
    data[c as usize] ^= g5(data[d as usize].wrapping_add(key[(7 * i as usize - 6 - 1) % 8]));
}

impl BeltBlock {
    #[inline]
    pub(crate) fn encrypt(&self, data: &mut [u8; 16]) {
        // Represent data as 4u32
        let data_u32 = unsafe {
            &mut *slice_from_raw_parts_mut(
                data.as_mut_ptr() as *mut u32,
                data.len() / core::mem::size_of::<u32>(),
            )
        };

        // Execution 2.1-2.9 steps of block encryption algorithm
        tact_enc(1, 0, 1, 2, 3, data_u32, &self.key);
        tact_enc(2, 1, 3, 0, 2, data_u32, &self.key);
        tact_enc(3, 3, 2, 1, 0, data_u32, &self.key);
        tact_enc(4, 2, 0, 3, 1, data_u32, &self.key);
        tact_enc(5, 0, 1, 2, 3, data_u32, &self.key);
        tact_enc(6, 1, 3, 0, 2, data_u32, &self.key);
        tact_enc(7, 3, 2, 1, 0, data_u32, &self.key);
        tact_enc(8, 2, 0, 3, 1, data_u32, &self.key);

        // 10) a<->b
        // 11) c<->d
        // 12) b<->c
        data_u32.swap(2, 3);
        data_u32.swap(0, 1);
        data_u32.swap(1, 2);
    }

    #[inline]
    pub(crate) fn decrypt(&self, data: &mut [u8; 16]) {
        // Represent data as 4u32
        let data_u32 = unsafe {
            &mut *slice_from_raw_parts_mut(
                data.as_mut_ptr() as *mut u32,
                data.len() / core::mem::size_of::<u32>(),
            )
        };

        // Execution 2.1-2.9 steps of block decryption algorithm
        tact_dec(8, 0, 1, 2, 3, data_u32, &self.key);
        tact_dec(7, 2, 0, 3, 1, data_u32, &self.key);
        tact_dec(6, 3, 2, 1, 0, data_u32, &self.key);
        tact_dec(5, 1, 3, 0, 2, data_u32, &self.key);
        tact_dec(4, 0, 1, 2, 3, data_u32, &self.key);
        tact_dec(3, 2, 0, 3, 1, data_u32, &self.key);
        tact_dec(2, 3, 2, 1, 0, data_u32, &self.key);
        tact_dec(1, 1, 3, 0, 2, data_u32, &self.key);

        // 10) a<->b
        // 11) c<->d
        // 12) a<->d
        data_u32.swap(2, 3);
        data_u32.swap(0, 3);
        data_u32.swap(1, 3);
    }
}

impl BlockCipher for BeltBlock {}

impl KeySizeUser for BeltBlock {
    type KeySize = U32;
}

impl KeyInit for BeltBlock {
    fn new(key: &Key<Self>) -> Self {
        let key: [u32; 8] = unsafe {
            (&*slice_from_raw_parts(
                key.as_ptr() as *const u32,
                key.len() / core::mem::size_of::<u32>(),
            ))
                .try_into()
                .unwrap()
        };

        Self { key }
    }
}

impl AlgorithmName for BeltBlock {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("belt-block")
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl Drop for BeltBlock {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl ZeroizeOnDrop for BeltBlock {}

cipher::impl_simple_block_encdec!(
    BeltBlock, U16, cipher, block,
    encrypt: {
        let mut data = block.clone_in().into();
        cipher.encrypt(&mut data);
        block.get_out().copy_from_slice(&data);
    }
    decrypt: {
        let mut data = block.clone_in().into();
        cipher.decrypt(&mut data);
        block.get_out().copy_from_slice(&data);
    }
);
