//
// Based on src/lib/block/camellia/camellia.cpp from https://github.com/randombit/botan
// Revision: 32bf9784bd6ee29cb3ffa173f0a734e9edce2dac
//

/*
 * Camellia
 * (C) 2012,2020 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

use core::fmt;

use byteorder::{ByteOrder, BE};
use cipher::{
    consts::{U16, U24, U32},
    AlgorithmName, BlockCipher, Key, KeyInit, KeySizeUser,
};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

use crate::consts::{SBOXES, SIGMAS};

/// F-function of component of Camellia defined in RFC 3713.
fn f(input: u64, key: u64) -> u64 {
    let x = (input ^ key).to_be_bytes();

    let z1 = 0x0101_0100_0100_0001 * u64::from(SBOXES[0][usize::from(x[0])]);
    let z2 = 0x0001_0101_0101_0000 * u64::from(SBOXES[1][usize::from(x[1])]);
    let z3 = 0x0100_0101_0001_0100 * u64::from(SBOXES[2][usize::from(x[2])]);
    let z4 = 0x0101_0001_0000_0101 * u64::from(SBOXES[3][usize::from(x[3])]);
    let z5 = 0x0001_0101_0001_0101 * u64::from(SBOXES[1][usize::from(x[4])]);
    let z6 = 0x0100_0101_0100_0101 * u64::from(SBOXES[2][usize::from(x[5])]);
    let z7 = 0x0101_0001_0101_0001 * u64::from(SBOXES[3][usize::from(x[6])]);
    let z8 = 0x0101_0100_0101_0100 * u64::from(SBOXES[0][usize::from(x[7])]);

    z1 ^ z2 ^ z3 ^ z4 ^ z5 ^ z6 ^ z7 ^ z8
}

/// FL-function of component of Camellia defined in RFC 3713.
fn fl(input: u64, key: u64) -> u64 {
    let mut x1 = u32::try_from(input >> 32).unwrap();
    let mut x2 = u32::try_from(input & 0xffff_ffff).unwrap();

    let k1 = u32::try_from(key >> 32).unwrap();
    let k2 = u32::try_from(key & 0xffff_ffff).unwrap();

    x2 ^= (x1 & k1).rotate_left(1);
    x1 ^= x2 | k2;

    (u64::from(x1) << 32) | u64::from(x2)
}

/// FLINV-function of component of Camellia defined in RFC 3713.
fn flinv(input: u64, key: u64) -> u64 {
    let mut y1 = u32::try_from(input >> 32).unwrap();
    let mut y2 = u32::try_from(input & 0xffff_ffff).unwrap();

    let k1 = u32::try_from(key >> 32).unwrap();
    let k2 = u32::try_from(key & 0xffff_ffff).unwrap();

    y1 ^= y2 | k2;
    y2 ^= (y1 & k1).rotate_left(1);

    (u64::from(y1) << 32) | u64::from(y2)
}

macro_rules! set_kl {
    ($key:expr) => {
        (
            u64::from_be_bytes($key[0..8].try_into().unwrap()),
            u64::from_be_bytes($key[8..16].try_into().unwrap()),
        )
    };
}

fn set_ka(kl: (u64, u64), kr: (u64, u64)) -> (u64, u64) {
    let mut d1 = kl.0 ^ kr.0;
    let mut d2 = kl.1 ^ kr.1;
    d2 ^= f(d1, SIGMAS[0]);
    d1 ^= f(d2, SIGMAS[1]);
    d1 ^= kl.0;
    d2 ^= kl.1;
    d2 ^= f(d1, SIGMAS[2]);
    d1 ^= f(d2, SIGMAS[3]);

    (d1, d2)
}

fn set_kb(ka: (u64, u64), kr: (u64, u64)) -> (u64, u64) {
    let mut d1 = ka.0 ^ kr.0;
    let mut d2 = ka.1 ^ kr.1;
    d2 ^= f(d1, SIGMAS[4]);
    d1 ^= f(d2, SIGMAS[5]);

    (d1, d2)
}

/// Performs rotate left and taking the higher-half of it.
fn rotate_left_high(val: (u64, u64), mut shift: u8) -> u64 {
    if shift >= 64 {
        shift -= 64;
    }

    (val.0 << shift) | (val.1 >> (64 - shift))
}

/// Performs rotate left and taking the lower-half of it.
fn rotate_left_low(val: (u64, u64), mut shift: u8) -> u64 {
    if shift >= 64 {
        shift -= 64;
    }

    (val.0 >> (64 - shift)) | (val.1 << shift)
}

impl Camellia128 {
    fn gen_subkeys(kl: (u64, u64), ka: (u64, u64)) -> Self {
        let mut k = [u64::default(); 26];

        k[0] = kl.0;
        k[1] = kl.1;

        k[2] = ka.0;
        k[3] = ka.1;
        k[4] = rotate_left_high(kl, 15);
        k[5] = rotate_left_low(kl, 15);
        k[6] = rotate_left_high(ka, 15);
        k[7] = rotate_left_low(ka, 15);

        k[8] = rotate_left_high(ka, 30);
        k[9] = rotate_left_low(ka, 30);

        k[10] = rotate_left_high(kl, 45);
        k[11] = rotate_left_low(kl, 45);
        k[12] = rotate_left_high(ka, 45);
        k[13] = rotate_left_low(kl, 60);
        k[14] = rotate_left_high(ka, 60);
        k[15] = rotate_left_low(ka, 60);

        k[16] = rotate_left_low(kl, 77);
        k[17] = rotate_left_high(kl, 77);

        k[18] = rotate_left_low(kl, 94);
        k[19] = rotate_left_high(kl, 94);
        k[20] = rotate_left_low(ka, 94);
        k[21] = rotate_left_high(ka, 94);
        k[22] = rotate_left_low(kl, 111);
        k[23] = rotate_left_high(kl, 111);

        k[24] = rotate_left_low(ka, 111);
        k[25] = rotate_left_high(ka, 111);

        Self { k }
    }
}

macro_rules! impl_gen_subkeys {
    ($name:ident) => {
        impl $name {
            fn gen_subkeys(kl: (u64, u64), kr: (u64, u64), ka: (u64, u64), kb: (u64, u64)) -> Self {
                let mut k = [u64::default(); 34];

                k[0] = kl.0;
                k[1] = kl.1;

                k[2] = kb.0;
                k[3] = kb.1;
                k[4] = rotate_left_high(kr, 15);
                k[5] = rotate_left_low(kr, 15);
                k[6] = rotate_left_high(ka, 15);
                k[7] = rotate_left_low(ka, 15);

                k[8] = rotate_left_high(kr, 30);
                k[9] = rotate_left_low(kr, 30);

                k[10] = rotate_left_high(kb, 30);
                k[11] = rotate_left_low(kb, 30);
                k[12] = rotate_left_high(kl, 45);
                k[13] = rotate_left_low(kl, 45);
                k[14] = rotate_left_high(ka, 45);
                k[15] = rotate_left_low(ka, 45);

                k[16] = rotate_left_high(kl, 60);
                k[17] = rotate_left_low(kl, 60);

                k[18] = rotate_left_high(kr, 60);
                k[19] = rotate_left_low(kr, 60);
                k[20] = rotate_left_high(kb, 60);
                k[21] = rotate_left_low(kb, 60);
                k[22] = rotate_left_low(kl, 77);
                k[23] = rotate_left_high(kl, 77);

                k[24] = rotate_left_low(ka, 77);
                k[25] = rotate_left_high(ka, 77);

                k[26] = rotate_left_low(kr, 94);
                k[27] = rotate_left_high(kr, 94);
                k[28] = rotate_left_low(ka, 94);
                k[29] = rotate_left_high(ka, 94);
                k[30] = rotate_left_low(kl, 111);
                k[31] = rotate_left_high(kl, 111);

                k[32] = rotate_left_low(kb, 111);
                k[33] = rotate_left_high(kb, 111);

                Self { k }
            }
        }
    };
}

impl_gen_subkeys!(Camellia192);
impl_gen_subkeys!(Camellia256);

impl KeyInit for Camellia128 {
    fn new(key: &Key<Self>) -> Self {
        let kl = set_kl!(key);
        let kr = (u64::default(), u64::default());

        let ka = set_ka(kl, kr);

        Self::gen_subkeys(kl, ka)
    }
}

impl KeyInit for Camellia192 {
    fn new(key: &Key<Self>) -> Self {
        let kl = set_kl!(key);
        let kr = u64::from_be_bytes(key[16..24].try_into().unwrap());
        let kr = (kr, !kr);

        let ka = set_ka(kl, kr);
        let kb = set_kb(ka, kr);

        Self::gen_subkeys(kl, kr, ka, kb)
    }
}

impl KeyInit for Camellia256 {
    fn new(key: &Key<Self>) -> Self {
        let kl = set_kl!(key);
        let kr = (
            u64::from_be_bytes(key[16..24].try_into().unwrap()),
            u64::from_be_bytes(key[24..32].try_into().unwrap()),
        );

        let ka = set_ka(kl, kr);
        let kb = set_kb(ka, kr);

        Self::gen_subkeys(kl, kr, ka, kb)
    }
}

macro_rules! impl_camellia {
    ($name:ident, $subkey_size:literal, $key_size:ty, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name {
            /// Subkeys.
            k: [u64; $subkey_size],
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
                self.k.zeroize();
            }
        }

        #[cfg(feature = "zeroize")]
        #[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
        impl ZeroizeOnDrop for $name {}

        cipher::impl_simple_block_encdec!(
            $name, U16, cipher, block,
            encrypt: {
                let b = block.get_in();
                let mut d1 = u64::from_be_bytes(b[0..8].try_into().unwrap());
                let mut d2 = u64::from_be_bytes(b[8..16].try_into().unwrap());

                d1 ^= cipher.k[0];
                d2 ^= cipher.k[1];

                for i in (2..$subkey_size - 2).step_by(2) {
                    if i % 8 == 0 {
                        d1 = fl(d1, cipher.k[i]);
                        d2 = flinv(d2, cipher.k[i + 1]);

                        continue;
                    }
                    d2 ^= f(d1, cipher.k[i]);
                    d1 ^= f(d2, cipher.k[i + 1]);
                }

                d2 ^= cipher.k[$subkey_size - 2];
                d1 ^= cipher.k[$subkey_size - 1];

                BE::write_u64_into(&[d2, d1], block.get_out());
            }
            decrypt: {
                let b = block.get_in();
                let mut d1 = u64::from_be_bytes(b[0..8].try_into().unwrap());
                let mut d2 = u64::from_be_bytes(b[8..16].try_into().unwrap());

                d2 ^= cipher.k[$subkey_size - 1];
                d1 ^= cipher.k[$subkey_size - 2];

                for i in (2..$subkey_size - 2).rev().step_by(2) {
                    if (i - 1) % 8 == 0 {
                        d1 = fl(d1, cipher.k[i]);
                        d2 = flinv(d2, cipher.k[i - 1]);

                        continue;
                    }
                    d2 ^= f(d1, cipher.k[i]);
                    d1 ^= f(d2, cipher.k[i - 1]);
                }

                d1 ^= cipher.k[1];
                d2 ^= cipher.k[0];

                BE::write_u64_into(&[d2, d1], block.get_out());
            }
        );
    };
}

impl_camellia!(Camellia128, 26, U16, "Camellia-128 block cipher instance.");
impl_camellia!(Camellia192, 34, U24, "Camellia-192 block cipher instance.");
impl_camellia!(Camellia256, 34, U32, "Camellia-256 block cipher instance.");
