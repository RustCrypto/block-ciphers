mod encdec;

use crate::Block;
use cipher::{
    AlgorithmName, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, Key, KeyInit,
    KeySizeUser, ParBlocks, ParBlocksSizeUser,
    consts::{U16, U24, U32, U64},
    crypto_common::WeakKeyError,
    inout::{InOut, InOutBuf},
};
use core::{arch::aarch64::uint8x16_t, fmt};

#[cfg(not(all(target_feature = "sve2-aes")))]
compile_error!("module requires aarch64 features `sve2-aes`");

type RoundKey = uint8x16_t;
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
                let key = key.as_ref();
                let round_keys = unsafe { crate::armv8::expand::expand_key(key) };
                Self { round_keys }
            }

            #[inline]
            fn weak_key_test(key: &Key<Self>) -> Result<(), WeakKeyError> {
                crate::weak_key_test(&key.0)
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

            #[inline]
            fn weak_key_test(key: &Key<Self>) -> Result<(), WeakKeyError> {
                crate::weak_key_test(&key.0)
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
                let round_keys = unsafe { crate::armv8::expand::inv_expanded_keys(&round_keys) };
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
                unsafe { crate::armv8::encdec::encrypt(&self.0.round_keys, block) };
            }

            #[inline(always)]
            fn encrypt_par_blocks(&self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
                self::encdec::$module::encrypt_all(&self.0.round_keys, blocks)
            }

            #[inline]
            fn encrypt_tail_blocks(&self, mut blocks: InOutBuf<'_, '_, Block>) {
                let len = blocks.len();
                match len {
                    0 => {}
                    1 => self.encrypt_block(blocks.get(0)),
                    len => {
                        let (iptr, optr) = blocks.into_raw();
                        let blocks = unsafe { InOut::from_raw(iptr.cast(), optr.cast()) };
                        self::encdec::$module::encrypt_vla(&self.0.round_keys, blocks, len)
                    }
                }
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
                unsafe { crate::armv8::encdec::decrypt(&self.0.round_keys, block) };
            }

            #[inline(always)]
            fn decrypt_par_blocks(&self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
                self::encdec::$module::decrypt_all(&self.0.round_keys, blocks)
            }

            #[inline]
            fn decrypt_tail_blocks(&self, mut blocks: InOutBuf<'_, '_, Block>) {
                let len = blocks.len();
                match len {
                    0 => {}
                    1 => self.decrypt_block(blocks.get(0)),
                    len => {
                        let (iptr, optr) = blocks.into_raw();
                        let blocks = unsafe { InOut::from_raw(iptr.cast(), optr.cast()) };
                        self::encdec::$module::decrypt_vla(&self.0.round_keys, blocks, len)
                    }
                }
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
