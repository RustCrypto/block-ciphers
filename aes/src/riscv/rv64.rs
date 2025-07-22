//! AES block cipher implementation for RISC-V 64 using Scalar Cryptography Extensions: Zkne, Zknd
//!
//! RISC-V Scalar Cryptography Extension v1.0.1:
//! https://github.com/riscv/riscv-crypto/releases/download/v1.0.1-scalar/riscv-crypto-spec-scalar-v1.0.1.pdf
//!
//! For reference, see the following other implementations:
//!
//!     1. The RISC-V Cryptography Extensions "benchmarks" reference for RISC-V 64 with Zkn{ed}:
//!     https://github.com/riscv/riscv-crypto/tree/main/benchmarks/aes/zscrypto_rv64
//!
//!     2. The OpenSSL implementation for RISC-V 64 with Zkn{ed}:
//!     https://github.com/openssl/openssl/blob/master/crypto/aes/asm/aes-riscv64-zkn.pl

#![cfg(not(all(target_feature = "zkne", target_feature = "zknd")))]
compile_error!("module requires riscv features `zkne` and `zknd`");

mod encdec;
pub(crate) mod expand;
#[cfg(test)]
pub(crate) mod test_expand;

pub(crate) type RoundKey = [u64; 2];
pub(crate) type RoundKeys<const N: usize> = [RoundKey; N];

use self::encdec::{decrypt1, decrypt8, encrypt1, encrypt8};
use self::expand::{KeySchedule, inv_expanded_keys};
use crate::riscv::Block;
use cipher::{
    AlgorithmName, Array, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, Key, KeyInit,
    KeySizeUser, ParBlocksSizeUser,
    consts::{U8, U16, U24, U32},
    crypto_common::WeakKeyError,
    inout::InOut,
};
use core::fmt;

pub(crate) type Block8 = Array<Block, cipher::consts::U8>;

macro_rules! define_aes_impl {
    (
        $name:ident,
        $name_enc:ident,
        $name_dec:ident,
        $name_back_enc:ident,
        $name_back_dec:ident,
        $key_size:ty,
        $words:tt,
        $rounds:tt,
        $doc:expr $(,)?
    ) => {
        #[doc=$doc]
        #[doc = "block cipher"]
        #[derive(Clone)]
        pub struct $name {
            encrypt: $name_enc,
            decrypt: $name_dec,
        }

        impl KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl KeyInit for $name {
            #[inline(always)]
            fn new(key: &Key<Self>) -> Self {
                let encrypt = $name_enc::new(key);
                let decrypt = $name_dec::from(&encrypt);
                Self { encrypt, decrypt }
            }

            #[inline(always)]
            fn weak_key_test(key: &Key<Self>) -> Result<(), WeakKeyError> {
                crate::weak_key_test(&key.0)
            }
        }

        impl From<$name_enc> for $name {
            #[inline(always)]
            fn from(encrypt: $name_enc) -> $name {
                let decrypt = (&encrypt).into();
                Self { encrypt, decrypt }
            }
        }

        impl From<&$name_enc> for $name {
            #[inline(always)]
            fn from(encrypt: &$name_enc) -> $name {
                let decrypt = encrypt.into();
                let encrypt = encrypt.clone();
                Self { encrypt, decrypt }
            }
        }

        impl BlockSizeUser for $name {
            type BlockSize = U16;
        }

        impl BlockCipherEncrypt for $name {
            fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = U16>) {
                self.encrypt.encrypt_with_backend(f)
            }
        }

        impl BlockCipherDecrypt for $name {
            fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = U16>) {
                self.decrypt.decrypt_with_backend(f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                f.write_str(concat!(stringify!($name), " { .. }"))
            }
        }

        impl AlgorithmName for $name {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($name))
            }
        }

        #[cfg(feature = "zeroize")]
        impl zeroize::ZeroizeOnDrop for $name {}

        #[doc=$doc]
        #[doc = "block cipher (encrypt-only)"]
        #[derive(Clone)]
        pub struct $name_enc {
            round_keys: RoundKeys<$rounds>,
        }

        impl $name_enc {
            #[inline(always)]
            pub(crate) fn get_enc_backend(&self) -> $name_back_enc<'_> {
                $name_back_enc(self)
            }
        }

        impl KeySizeUser for $name_enc {
            type KeySize = $key_size;
        }

        impl KeyInit for $name_enc {
            #[inline(always)]
            fn new(key: &Key<Self>) -> Self {
                Self {
                    round_keys: KeySchedule::<$words, $rounds>::expand_key(key.as_ref()),
                }
            }
        }

        impl BlockSizeUser for $name_enc {
            type BlockSize = U16;
        }

        impl BlockCipherEncrypt for $name_enc {
            fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = U16>) {
                f.call(&mut self.get_enc_backend())
            }
        }

        impl fmt::Debug for $name_enc {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                f.write_str(concat!(stringify!($name_enc), " { .. }"))
            }
        }

        impl AlgorithmName for $name_enc {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($name_enc))
            }
        }

        impl Drop for $name_enc {
            #[inline(always)]
            fn drop(&mut self) {
                #[cfg(feature = "zeroize")]
                zeroize::Zeroize::zeroize(&mut self.round_keys);
            }
        }

        #[cfg(feature = "zeroize")]
        impl zeroize::ZeroizeOnDrop for $name_enc {}

        #[doc=$doc]
        #[doc = "block cipher (decrypt-only)"]
        #[derive(Clone)]
        pub struct $name_dec {
            round_keys: RoundKeys<$rounds>,
        }

        impl $name_dec {
            #[inline(always)]
            pub(crate) fn get_dec_backend(&self) -> $name_back_dec<'_> {
                $name_back_dec(self)
            }
        }

        impl KeySizeUser for $name_dec {
            type KeySize = $key_size;
        }

        impl KeyInit for $name_dec {
            #[inline(always)]
            fn new(key: &Key<Self>) -> Self {
                $name_enc::new(key).into()
            }
        }

        impl From<$name_enc> for $name_dec {
            #[inline(always)]
            fn from(enc: $name_enc) -> $name_dec {
                Self::from(&enc)
            }
        }

        impl From<&$name_enc> for $name_dec {
            fn from(enc: &$name_enc) -> $name_dec {
                let mut round_keys = enc.round_keys;
                inv_expanded_keys(&mut round_keys);
                Self { round_keys }
            }
        }

        impl BlockSizeUser for $name_dec {
            type BlockSize = U16;
        }

        impl BlockCipherDecrypt for $name_dec {
            fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = U16>) {
                f.call(&mut self.get_dec_backend());
            }
        }

        impl fmt::Debug for $name_dec {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                f.write_str(concat!(stringify!($name_dec), " { .. }"))
            }
        }

        impl AlgorithmName for $name_dec {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($name_dec))
            }
        }

        impl Drop for $name_dec {
            #[inline(always)]
            fn drop(&mut self) {
                #[cfg(feature = "zeroize")]
                zeroize::Zeroize::zeroize(&mut self.round_keys);
            }
        }

        #[cfg(feature = "zeroize")]
        impl zeroize::ZeroizeOnDrop for $name_dec {}

        pub(crate) struct $name_back_enc<'a>(&'a $name_enc);

        impl<'a> BlockSizeUser for $name_back_enc<'a> {
            type BlockSize = U16;
        }

        impl<'a> ParBlocksSizeUser for $name_back_enc<'a> {
            type ParBlocksSize = U8;
        }

        impl<'a> BlockCipherEncBackend for $name_back_enc<'a> {
            #[inline(always)]
            fn encrypt_block(&self, block: InOut<'_, '_, Block>) {
                encrypt1(&self.0.round_keys, block);
            }

            #[inline(always)]
            fn encrypt_par_blocks(&self, blocks: InOut<'_, '_, cipher::ParBlocks<Self>>) {
                encrypt8(&self.0.round_keys, blocks)
            }
        }

        pub(crate) struct $name_back_dec<'a>(&'a $name_dec);

        impl<'a> BlockSizeUser for $name_back_dec<'a> {
            type BlockSize = U16;
        }

        impl<'a> ParBlocksSizeUser for $name_back_dec<'a> {
            type ParBlocksSize = U8;
        }

        impl<'a> BlockCipherDecBackend for $name_back_dec<'a> {
            #[inline(always)]
            fn decrypt_block(&self, block: InOut<'_, '_, Block>) {
                decrypt1(&self.0.round_keys, block);
            }

            #[inline(always)]
            fn decrypt_par_blocks(&self, blocks: InOut<'_, '_, cipher::ParBlocks<Self>>) {
                decrypt8(&self.0.round_keys, blocks)
            }
        }
    };
}

define_aes_impl!(
    Aes128,
    Aes128Enc,
    Aes128Dec,
    Aes128BackEnc,
    Aes128BackDec,
    U16,
    2,
    11,
    "AES-128",
);
define_aes_impl!(
    Aes192,
    Aes192Enc,
    Aes192Dec,
    Aes192BackEnc,
    Aes192BackDec,
    U24,
    3,
    13,
    "AES-192",
);
define_aes_impl!(
    Aes256,
    Aes256Enc,
    Aes256Dec,
    Aes256BackEnc,
    Aes256BackDec,
    U32,
    4,
    15,
    "AES-256",
);
