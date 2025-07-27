//! AES block cipher implementation using the RISC-V Vector Cryptography Extensions: Zvkned
//!
//! RISC-V Vector Cryptography Extension v1.0.0:
//! https://github.com/riscv/riscv-crypto/releases/download/v1.0.0/riscv-crypto-spec-vector.pdf
//!
//! For reference, see the following other implementations:
//!
//!     1. The RISC-V Cryptography Extensions vector code samples AES-CBC proof of concept with Zvkned:
//!     https://github.com/riscv/riscv-crypto/blob/main/doc/vector/code-samples/zvkned.s
//!
//!     2. The OpenSSL implementation for RISC-V 64 with Zvkned:
//!     https://github.com/openssl/openssl/blob/master/crypto/aes/asm/aes-riscv64-zvkned.pl

#![cfg(not(all(target_feature = "v", target_feature = "zvkned")))]
compile_error!("module requires riscv features `v` and `zvkned`");

mod encdec;
mod expand;
#[cfg(test)]
mod test_expand;

// TODO(silvanshade):
// - use scalar crypto for single blocks (test first; faster in QEMU though)
// - register allocation
// - use larger parallel block size
// - interleave key-schedule for parallel blocks (allows for larger LMUL)
// - use larger LMUL for parallel blocks

use crate::riscv::Block;
#[cfg(all(
    target_arch = "riscv64",
    target_feature = "zknd",
    target_feature = "zkne"
))]
use cipher::consts::U24;
use cipher::{
    AlgorithmName, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, Key, KeyInit,
    KeySizeUser, ParBlocksSizeUser,
    consts::{U16, U32, U64},
    crypto_common::WeakKeyError,
    inout::{InOut, InOutBuf},
};
use core::{fmt, num::NonZero};

type RoundKey = [u32; 4];
type RoundKeys<const N: usize> = [RoundKey; N];

macro_rules! define_aes_impl {
    (
        $module:ident,
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
            #[inline]
            fn new(key: &Key<Self>) -> Self {
                let encrypt = $name_enc::new(key);
                let decrypt = $name_dec::from(&encrypt);
                Self { encrypt, decrypt }
            }

            #[inline]
            fn weak_key_test(key: &Key<Self>) -> Result<(), WeakKeyError> {
                crate::weak_key_test(&key.0)
            }
        }

        impl From<$name_enc> for $name {
            #[inline]
            fn from(encrypt: $name_enc) -> $name {
                let decrypt = (&encrypt).into();
                Self { encrypt, decrypt }
            }
        }

        impl From<&$name_enc> for $name {
            #[inline]
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
            #[inline]
            fn new(key: &Key<Self>) -> Self {
                Self {
                    round_keys: self::expand::$module::expand_key(key.as_ref()),
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
            #[inline]
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
            #[inline]
            fn new(key: &Key<Self>) -> Self {
                $name_enc::new(key).into()
            }
        }

        impl From<$name_enc> for $name_dec {
            #[inline]
            fn from(enc: $name_enc) -> $name_dec {
                Self::from(&enc)
            }
        }

        impl From<&$name_enc> for $name_dec {
            fn from(enc: &$name_enc) -> $name_dec {
                let round_keys = enc.round_keys;
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
            #[inline]
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
            type ParBlocksSize = U64;
        }

        impl<'a> BlockCipherEncBackend for $name_back_enc<'a> {
            #[inline(always)]
            fn encrypt_block(&self, block: InOut<'_, '_, Block>) {
                self::encdec::$module::encrypt_one(&self.0.round_keys, block);
            }

            #[inline(always)]
            fn encrypt_par_blocks(&self, blocks: InOut<'_, '_, cipher::ParBlocks<Self>>) {
                self::encdec::$module::encrypt_many(&self.0.round_keys, blocks)
            }

            #[inline]
            fn encrypt_tail_blocks(&self, mut blocks: InOutBuf<'_, '_, Block>) {
                if let Some(len) = NonZero::new(blocks.len()).map(NonZero::get) {
                    self::encdec::$module::encrypt_vla(&self.0.round_keys, blocks.get(0), len)
                };
            }
        }

        pub(crate) struct $name_back_dec<'a>(&'a $name_dec);

        impl<'a> BlockSizeUser for $name_back_dec<'a> {
            type BlockSize = U16;
        }

        impl<'a> ParBlocksSizeUser for $name_back_dec<'a> {
            type ParBlocksSize = U64;
        }

        impl<'a> BlockCipherDecBackend for $name_back_dec<'a> {
            #[inline(always)]
            fn decrypt_block(&self, block: InOut<'_, '_, Block>) {
                self::encdec::$module::decrypt_one(&self.0.round_keys, block);
            }

            #[inline(always)]
            fn decrypt_par_blocks(&self, blocks: InOut<'_, '_, cipher::ParBlocks<Self>>) {
                self::encdec::$module::decrypt_many(&self.0.round_keys, blocks)
            }

            #[inline]
            fn decrypt_tail_blocks(&self, mut blocks: InOutBuf<'_, '_, Block>) {
                if let Some(len) = NonZero::new(blocks.len()).map(NonZero::get) {
                    self::encdec::$module::decrypt_vla(&self.0.round_keys, blocks.get(0), len)
                };
            }
        }
    };
}

define_aes_impl!(
    aes128,
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

// NOTE: AES-192 is only implemented for RVV if RISC-V scalar crypto is also
// enabled.
//
// This is because RVV does not provide key-expansion instructions for AES-192
// but we can fallback to the RISC-V scalar AES-192 key-expansion if available.
//
// If RISC-V scalar crypto is not available, then we fall back to the purely
// software based fixslice AES-192 implementation below
//
// # TODO:
//
// Use the fixslice or some other side-channel resistant AES-192 key-expansion
// while still taking advantage of RVV crypto even if RISC-V scalar crypto is
// unavailable.
//
// Maybe the best solution here would be to implement RVV accelerated fixslice.
// This would also be useful in the case where RVV is available but RVV crypto
// is not. Currently (2025) this is actually the most likely case anyway given
// the relative rarity of RVV crypto implementations.
#[cfg(all(
    target_arch = "riscv64",
    target_feature = "zknd",
    target_feature = "zkne"
))]
define_aes_impl!(
    aes192,
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
#[cfg(not(all(
    target_arch = "riscv64",
    target_feature = "zknd",
    target_feature = "zkne"
)))]
pub use crate::soft::Aes192;
define_aes_impl!(
    aes256,
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
