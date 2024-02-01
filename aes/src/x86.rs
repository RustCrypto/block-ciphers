pub(crate) mod ni;
#[cfg(target_arch = "x86_64")]
pub(crate) mod vaes256;
#[cfg(target_arch = "x86_64")]
pub(crate) mod vaes512;

#[cfg(target_arch = "x86")]
use core::arch::x86 as arch;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as arch;

use self::arch::*;
#[cfg(target_arch = "x86_64")]
use crate::Block32;
use crate::{Block, Block64, Block8};
use cipher::{
    consts::{U16, U24, U32, U64},
    inout::InOut,
    AlgorithmName, BlockBackend, BlockCipher, BlockCipherDecrypt, BlockCipherEncrypt, BlockClosure,
    BlockSizeUser, Key, KeyInit, KeySizeUser, ParBlocksSizeUser,
};
use core::fmt;

pub(crate) mod features {
    cpufeatures::new!(_aes, "aes");
    cpufeatures::new!(_avx, "avx");
    cpufeatures::new!(_avx512f, "avx512f");
    cpufeatures::new!(_vaes, "vaes");
    pub(crate) mod aes {
        pub use super::_aes::*;
    }
    #[cfg(target_arch = "x86_64")]
    pub(crate) mod avx {
        pub use super::_avx::*;
    }
    #[cfg(target_arch = "x86_64")]
    pub(crate) mod avx512f {
        pub use super::_avx512f::*;
    }
    #[cfg(target_arch = "x86_64")]
    pub(crate) mod vaes {
        pub use super::_vaes::*;
    }
}

type RoundKeys<const ROUNDS: usize> = [__m128i; ROUNDS];
#[cfg(target_arch = "x86_64")]
type Simd256RoundKeys<const ROUNDS: usize> = [__m256i; ROUNDS];
#[cfg(target_arch = "x86_64")]
type Simd512RoundKeys<const ROUNDS: usize> = [__m512i; ROUNDS];

macro_rules! define_aes_impl {
    (
        $name:tt,
        $name_enc:ident,
        $name_dec:ident,
        $name_back_enc:ident,
        $name_back_dec:ident,
        $module:tt,
        $key_size:ty,
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

        impl $name {
            #[inline(always)]
            pub(crate) fn get_enc_backend(&self) -> $name_back_enc<'_> {
                self.encrypt.get_enc_backend()
            }

            #[inline(always)]
            pub(crate) fn get_dec_backend(&self) -> $name_back_dec<'_> {
                self.decrypt.get_dec_backend()
            }
        }

        impl BlockCipher for $name {}

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
            #[inline]
            fn encrypt_with_backend(&self, f: impl BlockClosure<BlockSize = U16>) {
                self.encrypt.encrypt_with_backend(f)
            }
        }

        impl BlockCipherDecrypt for $name {
            #[inline]
            fn decrypt_with_backend(&self, f: impl BlockClosure<BlockSize = U16>) {
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
                $name_back_enc {
                    keys: &self.round_keys,
                    #[cfg(target_arch = "x86_64")]
                    simd_256_keys: None,
                    #[cfg(target_arch = "x86_64")]
                    simd_512_keys: None,
                    #[cfg(target_arch = "x86_64")]
                    avx_token: self::features::avx::init(),
                    #[cfg(target_arch = "x86_64")]
                    avx512f_token: self::features::avx512f::init(),
                    #[cfg(target_arch = "x86_64")]
                    vaes_token: self::features::vaes::init(),
                }
            }
        }

        impl BlockCipher for $name_enc {}

        impl KeySizeUser for $name_enc {
            type KeySize = $key_size;
        }

        impl KeyInit for $name_enc {
            #[inline]
            fn new(key: &Key<Self>) -> Self {
                // SAFETY: we enforce that this code is called only when
                // target features required by `expand` were properly checked.
                Self {
                    round_keys: unsafe { self::ni::$module::expand_key(key.as_ref()) },
                }
            }
        }

        impl BlockSizeUser for $name_enc {
            type BlockSize = U16;
        }

        impl BlockCipherEncrypt for $name_enc {
            #[inline]
            fn encrypt_with_backend(&self, f: impl BlockClosure<BlockSize = U16>) {
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
            #[inline]
            pub(crate) fn get_dec_backend(&self) -> $name_back_dec<'_> {
                $name_back_dec {
                    keys: &self.round_keys,
                    #[cfg(target_arch = "x86_64")]
                    simd_256_keys: None,
                    #[cfg(target_arch = "x86_64")]
                    simd_512_keys: None,
                    #[cfg(target_arch = "x86_64")]
                    avx_token: self::features::avx::init(),
                    #[cfg(target_arch = "x86_64")]
                    avx512f_token: self::features::avx512f::init(),
                    #[cfg(target_arch = "x86_64")]
                    vaes_token: self::features::vaes::init(),
                }
            }
        }

        impl BlockCipher for $name_dec {}

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
            #[inline]
            fn from(enc: &$name_enc) -> $name_dec {
                let round_keys = unsafe { self::ni::$module::inv_expanded_keys(&enc.round_keys) };
                Self { round_keys }
            }
        }

        impl BlockSizeUser for $name_dec {
            type BlockSize = U16;
        }

        impl BlockCipherDecrypt for $name_dec {
            #[inline]
            fn decrypt_with_backend(&self, f: impl BlockClosure<BlockSize = U16>) {
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

        pub(crate) struct $name_back_enc<'a> {
            keys: &'a RoundKeys<$rounds>,
            #[cfg(target_arch = "x86_64")]
            simd_256_keys: Option<Simd256RoundKeys<$rounds>>,
            #[cfg(target_arch = "x86_64")]
            simd_512_keys: Option<Simd512RoundKeys<$rounds>>,
            #[cfg(target_arch = "x86_64")]
            avx_token: self::features::avx::InitToken,
            #[cfg(target_arch = "x86_64")]
            avx512f_token: self::features::avx512f::InitToken,
            #[cfg(target_arch = "x86_64")]
            vaes_token: self::features::vaes::InitToken,
        }

        impl Drop for $name_back_enc<'_> {
            #[inline]
            fn drop(&mut self) {
                #[cfg(all(target_arch = "x86_64", feature = "zeroize"))]
                zeroize::Zeroize::zeroize(&mut self.simd_256_keys);
                // TODO: replace with `zeroize` method when Zeroize impl for `__m512i` is available
                #[cfg(all(target_arch = "x86_64", feature = "zeroize"))]
                if let Some(parallel_keys) = &mut self.simd_512_keys {
                    parallel_keys.iter_mut().for_each(|key| unsafe {
                        core::ptr::write_volatile(key, core::mem::zeroed());
                        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
                    });
                }
            }
        }

        impl<'a> BlockSizeUser for $name_back_enc<'a> {
            type BlockSize = U16;
        }

        impl<'a> ParBlocksSizeUser for $name_back_enc<'a> {
            type ParBlocksSize = U64;
        }

        impl<'a> BlockBackend for $name_back_enc<'a> {
            #[inline]
            fn proc_block(&mut self, block: InOut<'_, '_, Block>) {
                unsafe {
                    self::ni::$module::encrypt1(self.keys, block);
                }
            }

            #[inline]
            fn proc_par_blocks(&mut self, blocks: InOut<'_, '_, Block64>) {
                unsafe {
                    #[cfg(target_arch = "x86_64")]
                    if !cfg!(disable_avx512) && self.avx512f_token.get() && self.vaes_token.get() {
                        let simd_512_keys = self.simd_512_keys.get_or_insert_with(|| {
                            self::vaes512::$module::parallelize_keys(self.keys)
                        });
                        self::vaes512::$module::encrypt64(simd_512_keys, blocks);
                        return;
                    }
                    #[cfg(target_arch = "x86_64")]
                    if !cfg!(disable_avx256) && self.avx_token.get() && self.vaes_token.get() {
                        let simd_256_keys = self.simd_256_keys.get_or_insert_with(|| {
                            self::vaes256::$module::parallelize_keys(self.keys)
                        });
                        let (iptr, optr) = blocks.into_raw();
                        let iptr = iptr.cast::<Block32>();
                        let optr = optr.cast::<Block32>();
                        for i in 0..2 {
                            let blocks = InOut::from_raw(iptr.add(i), optr.add(i));
                            self::vaes256::$module::encrypt32(self.keys, simd_256_keys, blocks);
                        }
                        return;
                    }
                    let (iptr, optr) = blocks.into_raw();
                    let iptr = iptr.cast::<Block8>();
                    let optr = optr.cast::<Block8>();
                    for i in 0..8 {
                        let blocks = InOut::from_raw(iptr.add(i), optr.add(i));
                        self::ni::$module::encrypt8(self.keys, blocks);
                    }
                }
            }
        }

        pub(crate) struct $name_back_dec<'a> {
            keys: &'a RoundKeys<$rounds>,
            #[cfg(target_arch = "x86_64")]
            simd_256_keys: Option<Simd256RoundKeys<$rounds>>,
            #[cfg(target_arch = "x86_64")]
            simd_512_keys: Option<Simd512RoundKeys<$rounds>>,
            #[cfg(target_arch = "x86_64")]
            avx_token: self::features::avx::InitToken,
            #[cfg(target_arch = "x86_64")]
            avx512f_token: self::features::avx512f::InitToken,
            #[cfg(target_arch = "x86_64")]
            vaes_token: self::features::vaes::InitToken,
        }

        impl Drop for $name_back_dec<'_> {
            #[inline]
            fn drop(&mut self) {
                #[cfg(all(target_arch = "x86_64", feature = "zeroize"))]
                zeroize::Zeroize::zeroize(&mut self.simd_256_keys);
                // TODO: replace with `zeroize` method when Zeroize impl for `__m512i` is available
                #[cfg(all(target_arch = "x86_64", feature = "zeroize"))]
                if let Some(parallel_keys) = &mut self.simd_512_keys {
                    parallel_keys.iter_mut().for_each(|key| unsafe {
                        core::ptr::write_volatile(key, core::mem::zeroed());
                        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
                    });
                }
            }
        }

        impl<'a> BlockSizeUser for $name_back_dec<'a> {
            type BlockSize = U16;
        }

        impl<'a> ParBlocksSizeUser for $name_back_dec<'a> {
            type ParBlocksSize = U64;
        }

        impl<'a> BlockBackend for $name_back_dec<'a> {
            #[inline]
            fn proc_block(&mut self, block: InOut<'_, '_, Block>) {
                unsafe {
                    self::ni::$module::decrypt1(self.keys, block);
                }
            }

            #[inline]
            fn proc_par_blocks(&mut self, blocks: InOut<'_, '_, Block64>) {
                unsafe {
                    #[cfg(target_arch = "x86_64")]
                    if !cfg!(disable_avx512) && self.avx512f_token.get() && self.vaes_token.get() {
                        let simd_512_keys = self.simd_512_keys.get_or_insert_with(|| {
                            self::vaes512::$module::parallelize_keys(self.keys)
                        });
                        self::vaes512::$module::decrypt64(simd_512_keys, blocks);
                        return;
                    }
                    #[cfg(target_arch = "x86_64")]
                    if !cfg!(disable_avx256) && self.avx_token.get() && self.vaes_token.get() {
                        let simd_256_keys = self.simd_256_keys.get_or_insert_with(|| {
                            self::vaes256::$module::parallelize_keys(self.keys)
                        });
                        let (iptr, optr) = blocks.into_raw();
                        let iptr = iptr.cast::<Block32>();
                        let optr = optr.cast::<Block32>();
                        for i in 0..2 {
                            let blocks = InOut::from_raw(iptr.add(i), optr.add(i));
                            self::vaes256::$module::decrypt32(self.keys, simd_256_keys, blocks);
                        }
                        return;
                    }
                    let (iptr, optr) = blocks.into_raw();
                    let iptr = iptr.cast::<Block8>();
                    let optr = optr.cast::<Block8>();
                    for i in 0..8 {
                        let blocks = InOut::from_raw(iptr.add(i), optr.add(i));
                        self::ni::$module::decrypt8(self.keys, blocks);
                    }
                }
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
    aes128,
    U16,
    11,
    "AES-128",
);

define_aes_impl!(
    Aes192,
    Aes192Enc,
    Aes192Dec,
    Aes192BackEnc,
    Aes192BackDec,
    aes192,
    U24,
    13,
    "AES-192",
);

define_aes_impl!(
    Aes256,
    Aes256Enc,
    Aes256Dec,
    Aes256BackEnc,
    Aes256BackDec,
    aes256,
    U32,
    15,
    "AES-256",
);
