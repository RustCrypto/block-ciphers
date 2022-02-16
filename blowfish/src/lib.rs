//! Pure Rust implementation of the [Blowfish] block cipher.
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate implements only the low-level block cipher function, and is intended
//! for use for implementing higher-level constructions *only*. It is NOT
//! intended for direct use in applications.
//!
//! USE AT YOUR OWN RISK!
//!
//! [Blowfish]: https://en.wikipedia.org/wiki/Blowfish_(cipher)

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_root_url = "https://docs.rs/blowfish/0.9.1"
)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

pub use cipher;

use byteorder::{ByteOrder, BE, LE};
use cipher::{
    consts::{U56, U8},
    AlgorithmName, BlockCipher, InvalidLength, Key, KeyInit, KeySizeUser,
};
use core::fmt;
use core::marker::PhantomData;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

mod consts;

/// Blowfish variant which uses Little Endian byte order read/writes.s.
pub type BlowfishLE = Blowfish<LE>;

/// Blowfish block cipher instance.
#[derive(Clone)]
pub struct Blowfish<T: ByteOrder = BE> {
    s: [[u32; 256]; 4],
    p: [u32; 18],
    _pd: PhantomData<T>,
}

fn next_u32_wrap(buf: &[u8], offset: &mut usize) -> u32 {
    let mut v = 0;
    for _ in 0..4 {
        if *offset >= buf.len() {
            *offset = 0;
        }
        v = (v << 8) | buf[*offset] as u32;
        *offset += 1;
    }
    v
}

impl<T: ByteOrder> Blowfish<T> {
    fn init_state() -> Blowfish<T> {
        Blowfish {
            p: consts::P,
            s: consts::S,
            _pd: PhantomData,
        }
    }

    fn expand_key(&mut self, key: &[u8]) {
        let mut key_pos = 0;
        for i in 0..18 {
            self.p[i] ^= next_u32_wrap(key, &mut key_pos);
        }
        let mut lr = [0u32; 2];
        for i in 0..9 {
            lr = self.encrypt(lr);
            self.p[2 * i] = lr[0];
            self.p[2 * i + 1] = lr[1];
        }
        for i in 0..4 {
            for j in 0..128 {
                lr = self.encrypt(lr);
                self.s[i][2 * j] = lr[0];
                self.s[i][2 * j + 1] = lr[1];
            }
        }
    }

    #[allow(clippy::many_single_char_names)]
    fn round_function(&self, x: u32) -> u32 {
        let a = self.s[0][(x >> 24) as usize];
        let b = self.s[1][((x >> 16) & 0xff) as usize];
        let c = self.s[2][((x >> 8) & 0xff) as usize];
        let d = self.s[3][(x & 0xff) as usize];
        (a.wrapping_add(b) ^ c).wrapping_add(d)
    }

    fn encrypt(&self, [mut l, mut r]: [u32; 2]) -> [u32; 2] {
        for i in 0..8 {
            l ^= self.p[2 * i];
            r ^= self.round_function(l);
            r ^= self.p[2 * i + 1];
            l ^= self.round_function(r);
        }
        l ^= self.p[16];
        r ^= self.p[17];
        [r, l]
    }

    fn decrypt(&self, [mut l, mut r]: [u32; 2]) -> [u32; 2] {
        for i in (1..9).rev() {
            l ^= self.p[2 * i + 1];
            r ^= self.round_function(l);
            r ^= self.p[2 * i];
            l ^= self.round_function(r);
        }
        l ^= self.p[1];
        r ^= self.p[0];
        [r, l]
    }
}

impl<T: ByteOrder> BlockCipher for Blowfish<T> {}

impl<T: ByteOrder> KeySizeUser for Blowfish<T> {
    type KeySize = U56;
}

impl<T: ByteOrder> KeyInit for Blowfish<T> {
    fn new(key: &Key<Self>) -> Self {
        Self::new_from_slice(&key[..]).unwrap()
    }

    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        if key.len() < 4 || key.len() > 56 {
            return Err(InvalidLength);
        }
        let mut blowfish = Blowfish::init_state();
        blowfish.expand_key(key);
        Ok(blowfish)
    }
}

impl fmt::Debug for Blowfish<BE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Blowfish<BE> { ... }")
    }
}

impl AlgorithmName for Blowfish<BE> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Blowfish<BE>")
    }
}

impl fmt::Debug for Blowfish<LE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Blowfish<LE> { ... }")
    }
}

impl AlgorithmName for Blowfish<LE> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Blowfish<LE>")
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<T: ByteOrder> Drop for Blowfish<T> {
    fn drop(&mut self) {
        self.s.zeroize();
        self.p.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<T: ByteOrder> ZeroizeOnDrop for Blowfish<T> {}

cipher::impl_simple_block_encdec!(
    <T: ByteOrder> Blowfish, U8, cipher, block,
    encrypt: {
        let mut b = [0u32; 2];
        T::read_u32_into(block.get_in(), &mut b);
        b = cipher.encrypt(b);
        T::write_u32_into(&b, block.get_out());
    }
    decrypt: {
        let mut b = [0u32; 2];
        T::read_u32_into(block.get_in(), &mut b);
        b = cipher.decrypt(b);
        T::write_u32_into(&b, block.get_out());
    }
);

/// Bcrypt extension of blowfish
#[cfg(feature = "bcrypt")]
impl Blowfish<BE> {
    /// Salted expand key
    pub fn salted_expand_key(&mut self, salt: &[u8], key: &[u8]) {
        let mut key_pos = 0;
        for i in 0..18 {
            self.p[i] ^= next_u32_wrap(key, &mut key_pos);
        }
        let mut lr = [0u32; 2];
        let mut salt_pos = 0;
        for i in 0..9 {
            lr[0] ^= next_u32_wrap(salt, &mut salt_pos);
            lr[1] ^= next_u32_wrap(salt, &mut salt_pos);
            lr = self.encrypt(lr);

            self.p[2 * i] = lr[0];
            self.p[2 * i + 1] = lr[1];
        }
        for i in 0..4 {
            for j in 0..64 {
                lr[0] ^= next_u32_wrap(salt, &mut salt_pos);
                lr[1] ^= next_u32_wrap(salt, &mut salt_pos);
                lr = self.encrypt(lr);

                self.s[i][4 * j] = lr[0];
                self.s[i][4 * j + 1] = lr[1];

                lr[0] ^= next_u32_wrap(salt, &mut salt_pos);
                lr[1] ^= next_u32_wrap(salt, &mut salt_pos);
                lr = self.encrypt(lr);

                self.s[i][4 * j + 2] = lr[0];
                self.s[i][4 * j + 3] = lr[1];
            }
        }
    }

    /// Init state
    pub fn bc_init_state() -> Blowfish<BE> {
        Blowfish::init_state()
    }

    /// Encrypt
    pub fn bc_encrypt(&self, lr: [u32; 2]) -> [u32; 2] {
        self.encrypt(lr)
    }

    /// Expand key
    pub fn bc_expand_key(&mut self, key: &[u8]) {
        self.expand_key(key)
    }
}
