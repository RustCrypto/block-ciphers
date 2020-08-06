//! Implementation of the [block cipher][1] defined in GOST 28147-89
//! and GOST R 34.12-2015.
//!
//! # Examples
//! ```
//! use magma::{Magma, BlockCipher, NewBlockCipher};
//! use magma::block_cipher::generic_array::GenericArray;
//! use hex_literal::hex;
//!
//! // Example vector from GOST 34.12-2018
//! let key = hex!("
//!     FFEEDDCCBBAA99887766554433221100
//!     F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF
//! ");
//! let plaintext = hex!("FEDCBA9876543210");
//! let ciphertext = hex!("4EE901E5C2D8CA3D");
//!
//! let cipher = Magma::new(GenericArray::from_slice(&key));
//!
//! let mut block = GenericArray::clone_from_slice(&plaintext);
//! cipher.encrypt_block(&mut block);
//! assert_eq!(&ciphertext, block.as_slice());
//!
//! cipher.decrypt_block(&mut block);
//! assert_eq!(&plaintext, block.as_slice());
//! ```
//!
//! [1]: https://en.wikipedia.org/wiki/GOST_(block_cipher)
#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![deny(unsafe_code)]
#![warn(rust_2018_idioms)]

pub use block_cipher;
use block_cipher::consts::{U1, U32, U8};
use block_cipher::generic_array::GenericArray;
pub use block_cipher::{BlockCipher, NewBlockCipher};
use core::{convert::TryInto, marker::PhantomData};

mod sboxes;

pub use sboxes::Sbox;

/// Block cipher defined in GOST 28147-89 generic over S-box
#[derive(Clone, Copy)]
pub struct Gost89<S: Sbox> {
    key: [u32; 8],
    _p: PhantomData<S>,
}

impl<S: Sbox> NewBlockCipher for Gost89<S> {
    type KeySize = U32;

    fn new(key: &GenericArray<u8, U32>) -> Self {
        let mut key_u32 = [0u32; 8];
        key.chunks_exact(4)
            .zip(key_u32.iter_mut())
            .for_each(|(chunk, v)| *v = to_u32(chunk));
        Self {
            key: key_u32,
            _p: Default::default(),
        }
    }
}

impl<S: Sbox> BlockCipher for Gost89<S> {
    type BlockSize = U8;
    type ParBlocks = U1;

    #[inline]
    fn encrypt_block(&self, block: &mut GenericArray<u8, U8>) {
        let mut v = (to_u32(&block[0..4]), to_u32(&block[4..8]));
        for _ in 0..3 {
            for i in 0..8 {
                v = (v.1, v.0 ^ S::g(v.1, self.key[i]));
            }
        }
        for i in (0..8).rev() {
            v = (v.1, v.0 ^ S::g(v.1, self.key[i]));
        }
        block[0..4].copy_from_slice(&v.1.to_be_bytes());
        block[4..8].copy_from_slice(&v.0.to_be_bytes());
    }

    #[inline]
    fn decrypt_block(&self, block: &mut GenericArray<u8, U8>) {
        let mut v = (to_u32(&block[0..4]), to_u32(&block[4..8]));

        for i in 0..8 {
            v = (v.1, v.0 ^ S::g(v.1, self.key[i]));
        }

        for _ in 0..3 {
            for i in (0..8).rev() {
                v = (v.1, v.0 ^ S::g(v.1, self.key[i]));
            }
        }
        block[0..4].copy_from_slice(&v.1.to_be_bytes());
        block[4..8].copy_from_slice(&v.0.to_be_bytes());
    }
}

/// Block cipher defined in GOST R 34.12-2015 (Magma)
pub type Magma = Gost89<sboxes::Tc26>;
/// Block cipher defined in GOST 28147-89 with test S-box
pub type Gost89Test = Gost89<sboxes::TestSbox>;
/// Block cipher defined in GOST 28147-89 with CryptoPro S-box version A
pub type Gost89CryptoProA = Gost89<sboxes::CryptoProA>;
/// Block cipher defined in GOST 28147-89 with CryptoPro S-box version B
pub type Gost89CryptoProB = Gost89<sboxes::CryptoProB>;
/// Block cipher defined in GOST 28147-89 with CryptoPro S-box version C
pub type Gost89CryptoProC = Gost89<sboxes::CryptoProC>;
/// Block cipher defined in GOST 28147-89 with CryptoPro S-box version D
pub type Gost89CryptoProD = Gost89<sboxes::CryptoProD>;

fn to_u32(chunk: &[u8]) -> u32 {
    u32::from_be_bytes(chunk.try_into().unwrap())
}
