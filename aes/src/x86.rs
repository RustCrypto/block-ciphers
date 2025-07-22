pub(crate) mod ni;
#[cfg(all(target_arch = "x86_64", any(aes_avx256, aes_avx512)))]
pub(crate) mod vaes256;
#[cfg(all(target_arch = "x86_64", aes_avx512))]
pub(crate) mod vaes512;

#[cfg(target_arch = "x86")]
use core::arch::x86 as arch;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as arch;

use self::arch::*;
use crate::Block;
#[cfg(all(target_arch = "x86_64", aes_avx512))]
use cipher::consts::U64;
use cipher::{
    AlgorithmName, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, InOut, Key,
    KeyInit, KeySizeUser, ParBlocksSizeUser,
    consts::{U9, U16, U24, U32},
    crypto_common::WeakKeyError,
};
#[cfg(all(target_arch = "x86_64", any(aes_avx256, aes_avx512)))]
use cipher::{Array, InOutBuf, consts::U30, typenum::Unsigned};
#[cfg(all(target_arch = "x86_64", any(aes_avx256, aes_avx512)))]
use core::cell::OnceCell;
use core::fmt;

#[cfg(all(target_arch = "x86_64", any(aes_avx256, aes_avx512)))]
pub(crate) type Block30 = Array<Block, U30>;
#[cfg(all(target_arch = "x86_64", aes_avx512))]
pub(crate) type Block64 = Array<Block, U64>;

pub(crate) mod features {
    cpufeatures::new!(features_aes, "aes");
    cpufeatures::new!(features_avx, "avx");
    cpufeatures::new!(features_avx512f, "avx512f");
    cpufeatures::new!(features_vaes, "vaes");
    pub(crate) mod aes {
        pub use super::features_aes::*;
    }
    #[cfg(all(target_arch = "x86_64", any(aes_avx256, aes_avx512)))]
    pub(crate) mod avx {
        pub use super::features_avx::*;
    }
    #[cfg(all(target_arch = "x86_64", aes_avx512))]
    pub(crate) mod avx512f {
        pub use super::features_avx512f::*;
    }
    #[cfg(all(target_arch = "x86_64", any(aes_avx256, aes_avx512)))]
    pub(crate) mod vaes {
        pub use super::features_vaes::*;
    }
}

type Simd128RoundKeys<const ROUNDS: usize> = [__m128i; ROUNDS];
#[cfg(all(target_arch = "x86_64", any(aes_avx256, aes_avx512)))]
type Simd256RoundKeys<const ROUNDS: usize> = [__m256i; ROUNDS];
#[cfg(all(target_arch = "x86_64", aes_avx512))]
type Simd512RoundKeys<const ROUNDS: usize> = [__m512i; ROUNDS];

#[derive(Clone)]
enum Backend {
    Ni,
    #[cfg(all(target_arch = "x86_64", any(aes_avx256, aes_avx512)))]
    Vaes256,
    #[cfg(all(target_arch = "x86_64", aes_avx512))]
    Vaes512,
}

#[derive(Clone, Copy)]
struct Features {
    #[cfg(all(target_arch = "x86_64", any(aes_avx256, aes_avx512)))]
    avx: self::features::avx::InitToken,
    #[cfg(all(target_arch = "x86_64", aes_avx512))]
    avx512f: self::features::avx512f::InitToken,
    #[cfg(all(target_arch = "x86_64", any(aes_avx256, aes_avx512)))]
    vaes: self::features::vaes::InitToken,
}

impl Features {
    fn new() -> Self {
        Self {
            #[cfg(all(target_arch = "x86_64", any(aes_avx256, aes_avx512)))]
            avx: self::features::avx::init(),
            #[cfg(all(target_arch = "x86_64", aes_avx512))]
            avx512f: self::features::avx512f::init(),
            #[cfg(all(target_arch = "x86_64", any(aes_avx256, aes_avx512)))]
            vaes: self::features::vaes::init(),
        }
    }

    #[cfg(all(target_arch = "x86_64", any(aes_avx256, aes_avx512)))]
    fn has_vaes256(&self) -> bool {
        #[cfg(target_arch = "x86_64")]
        if cfg!(aes_avx256) && self.vaes.get() && self.avx.get() {
            return true;
        }
        false
    }

    #[cfg(all(target_arch = "x86_64", aes_avx512))]
    fn has_vaes512(&self) -> bool {
        #[cfg(target_arch = "x86_64")]
        if cfg!(aes_avx512) && self.vaes.get() && self.avx512f.get() {
            return true;
        }
        false
    }

    fn dispatch(&self) -> Backend {
        #[cfg(all(target_arch = "x86_64", aes_avx512))]
        if self.has_vaes512() {
            return self::Backend::Vaes512;
        }
        #[cfg(all(target_arch = "x86_64", any(aes_avx256, aes_avx512)))]
        if self.has_vaes256() {
            return self::Backend::Vaes256;
        }
        Backend::Ni
    }
}

macro_rules! define_aes_impl {
    (
        $name:tt,
        $name_enc:ident,
        $name_dec:ident,
        $name_backend:ident,
        $module:tt,
        $key_size:ty,
        $rounds:tt,
        $doc:expr $(,)?
    ) => {
        mod $name_backend {
            use super::*;

            #[derive(Clone)]
            pub(crate) struct Ni<'a> {
                pub(crate) keys: &'a Simd128RoundKeys<$rounds>,
            }
            #[cfg(all(target_arch = "x86_64", any(aes_avx256, aes_avx512)))]
            impl<'a> Ni<'a> {
                pub const fn par_blocks(&self) -> usize {
                    <Self as ParBlocksSizeUser>::ParBlocksSize::USIZE
                }
            }
            #[cfg(all(target_arch = "x86_64", any(aes_avx256, aes_avx512)))]
            impl<'a> From<&Vaes256<'a>> for Ni<'a> {
                fn from(backend: &Vaes256<'a>) -> Self {
                    Self { keys: backend.keys }
                }
            }

            #[cfg(all(target_arch = "x86_64", any(aes_avx256, aes_avx512)))]
            #[derive(Clone)]
            pub(crate) struct Vaes256<'a> {
                #[allow(unused)] // TODO: remove once cfg flags are removed
                pub(crate) features: Features,
                pub(crate) keys: &'a Simd128RoundKeys<$rounds>,
                pub(crate) simd_256_keys: OnceCell<Simd256RoundKeys<$rounds>>,
            }
            #[cfg(all(target_arch = "x86_64", any(aes_avx256, aes_avx512)))]
            impl<'a> Vaes256<'a> {
                #[allow(unused)] // TODO: remove once cfg flags are removed
                pub const fn par_blocks(&self) -> usize {
                    <Self as ParBlocksSizeUser>::ParBlocksSize::USIZE
                }
            }
            #[cfg(all(target_arch = "x86_64", aes_avx512))]
            impl<'a> From<&Vaes512<'a>> for Vaes256<'a> {
                fn from(backend: &Vaes512<'a>) -> Self {
                    Self {
                        features: backend.features,
                        keys: backend.keys,
                        simd_256_keys: OnceCell::new(),
                    }
                }
            }

            #[cfg(all(target_arch = "x86_64", aes_avx512))]
            pub(crate) struct Vaes512<'a> {
                pub(crate) features: Features,
                pub(crate) keys: &'a Simd128RoundKeys<$rounds>,
                pub(crate) simd_512_keys: OnceCell<Simd512RoundKeys<$rounds>>,
            }
        }

        #[doc=$doc]
        #[doc = "block cipher"]
        #[derive(Clone)]
        pub struct $name {
            encrypt: $name_enc,
            decrypt: $name_dec,
        }

        #[cfg(feature = "zeroize")]
        impl zeroize::ZeroizeOnDrop for $name {}

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
            #[inline]
            fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = U16>) {
                self.encrypt.encrypt_with_backend(f)
            }
        }

        impl BlockCipherDecrypt for $name {
            #[inline]
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

        #[doc=$doc]
        #[doc = "block cipher (encrypt-only)"]
        #[derive(Clone)]
        pub struct $name_enc {
            keys: Simd128RoundKeys<$rounds>,
            features: Features,
        }

        impl Drop for $name_enc {
            fn drop(&mut self) {
                #[cfg(feature = "zeroize")]
                unsafe {
                    zeroize::zeroize_flat_type(&mut self.keys)
                }
            }
        }

        #[cfg(feature = "zeroize")]
        impl zeroize::ZeroizeOnDrop for $name_enc {}

        impl KeySizeUser for $name_enc {
            type KeySize = $key_size;
        }

        impl KeyInit for $name_enc {
            #[inline]
            fn new(key: &Key<Self>) -> Self {
                // SAFETY: we enforce that this code is called only when
                // target features required by `expand` were properly checked.
                Self {
                    keys: unsafe { self::ni::expand::$module::expand_key(key.as_ref()) },
                    features: Features::new(),
                }
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
            #[inline]
            fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = U16>) {
                let features = self.features;
                let keys = &self.keys;
                match features.dispatch() {
                    self::Backend::Ni => f.call(&mut $name_backend::Ni { keys }),
                    #[cfg(all(target_arch = "x86_64", any(aes_avx256, aes_avx512)))]
                    self::Backend::Vaes256 => f.call(&mut $name_backend::Vaes256 {
                        features,
                        keys,
                        simd_256_keys: OnceCell::new(),
                    }),
                    #[cfg(all(target_arch = "x86_64", aes_avx512))]
                    self::Backend::Vaes512 => f.call(&mut $name_backend::Vaes512 {
                        features,
                        keys,
                        simd_512_keys: OnceCell::new(),
                    }),
                }
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

        #[doc=$doc]
        #[doc = "block cipher (decrypt-only)"]
        #[derive(Clone)]
        pub struct $name_dec {
            keys: Simd128RoundKeys<$rounds>,
            features: Features,
        }

        impl Drop for $name_dec {
            fn drop(&mut self) {
                #[cfg(feature = "zeroize")]
                unsafe {
                    zeroize::zeroize_flat_type(&mut self.keys)
                }
            }
        }

        #[cfg(feature = "zeroize")]
        impl zeroize::ZeroizeOnDrop for $name_dec {}

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
            #[inline]
            fn from(enc: &$name_enc) -> $name_dec {
                Self {
                    keys: unsafe { self::ni::expand::inv_keys(&enc.keys) },
                    features: enc.features.clone(),
                }
            }
        }

        impl BlockSizeUser for $name_dec {
            type BlockSize = U16;
        }

        impl BlockCipherDecrypt for $name_dec {
            #[inline]
            fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = U16>) {
                let features = self.features;
                let keys = &self.keys;
                match features.dispatch() {
                    self::Backend::Ni => f.call(&mut $name_backend::Ni { keys }),
                    #[cfg(all(target_arch = "x86_64", any(aes_avx256, aes_avx512)))]
                    self::Backend::Vaes256 => f.call(&mut $name_backend::Vaes256 {
                        features,
                        keys,
                        simd_256_keys: OnceCell::new(),
                    }),
                    #[cfg(all(target_arch = "x86_64", aes_avx512))]
                    self::Backend::Vaes512 => f.call(&mut $name_backend::Vaes512 {
                        features,
                        keys,
                        simd_512_keys: OnceCell::new(),
                    }),
                }
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

        impl<'a> BlockSizeUser for $name_backend::Ni<'a> {
            type BlockSize = U16;
        }
        #[cfg(all(target_arch = "x86_64", any(aes_avx256, aes_avx512)))]
        impl<'a> BlockSizeUser for $name_backend::Vaes256<'a> {
            type BlockSize = U16;
        }
        #[cfg(all(target_arch = "x86_64", aes_avx512))]
        impl<'a> BlockSizeUser for $name_backend::Vaes512<'a> {
            type BlockSize = U16;
        }

        impl<'a> ParBlocksSizeUser for $name_backend::Ni<'a> {
            type ParBlocksSize = U9;
        }
        #[cfg(all(target_arch = "x86_64", any(aes_avx256, aes_avx512)))]
        impl<'a> ParBlocksSizeUser for $name_backend::Vaes256<'a> {
            type ParBlocksSize = U30;
        }
        #[cfg(all(target_arch = "x86_64", aes_avx512))]
        impl<'a> ParBlocksSizeUser for $name_backend::Vaes512<'a> {
            type ParBlocksSize = U64;
        }

        impl<'a> BlockCipherEncBackend for $name_backend::Ni<'a> {
            #[inline]
            fn encrypt_block(&self, block: InOut<'_, '_, Block>) {
                unsafe {
                    self::ni::encdec::encrypt(self.keys, block);
                }
            }
            #[inline]
            fn encrypt_par_blocks(&self, blocks: InOut<'_, '_, cipher::ParBlocks<Self>>) {
                unsafe {
                    self::ni::encdec::encrypt_par(self.keys, blocks);
                }
            }
        }
        #[cfg(all(target_arch = "x86_64", any(aes_avx256, aes_avx512)))]
        impl<'a> BlockCipherEncBackend for $name_backend::Vaes256<'a> {
            #[inline]
            fn encrypt_block(&self, block: InOut<'_, '_, Block>) {
                unsafe {
                    self::ni::encdec::encrypt(self.keys, block);
                }
            }
            #[inline]
            fn encrypt_par_blocks(&self, blocks: InOut<'_, '_, cipher::ParBlocks<Self>>) {
                unsafe {
                    let simd_256_keys = self
                        .simd_256_keys
                        .get_or_init(|| vaes256::encdec::broadcast_keys(&self.keys));
                    vaes256::encdec::encrypt30(simd_256_keys, blocks);
                }
            }
            #[inline]
            fn encrypt_tail_blocks(&self, blocks: InOutBuf<'_, '_, Block>) {
                let backend = self;

                let mut rem = blocks.len();
                let (mut iptr, mut optr) = blocks.into_raw();

                let backend = $name_backend::Ni::from(backend);
                while rem >= backend.par_blocks() {
                    let blocks = unsafe { InOut::from_raw(iptr.cast(), optr.cast()) };
                    backend.encrypt_par_blocks(blocks);
                    rem -= backend.par_blocks();
                    iptr = unsafe { iptr.add(backend.par_blocks()) };
                    optr = unsafe { optr.add(backend.par_blocks()) };
                }

                while rem > 0 {
                    let block = unsafe { InOut::from_raw(iptr, optr) };
                    backend.encrypt_block(block);
                    rem -= 1;
                    iptr = unsafe { iptr.add(1) };
                    optr = unsafe { optr.add(1) };
                }
            }
        }
        #[cfg(all(target_arch = "x86_64", aes_avx512))]
        impl<'a> BlockCipherEncBackend for $name_backend::Vaes512<'a> {
            #[inline]
            fn encrypt_block(&self, block: InOut<'_, '_, Block>) {
                unsafe {
                    self::ni::encdec::encrypt(self.keys, block);
                }
            }
            #[inline]
            fn encrypt_par_blocks(&self, blocks: InOut<'_, '_, cipher::ParBlocks<Self>>) {
                unsafe {
                    let simd_512_keys = self
                        .simd_512_keys
                        .get_or_init(|| vaes512::encdec::broadcast_keys(&self.keys));
                    vaes512::encdec::encrypt64(simd_512_keys, blocks);
                }
            }
            #[inline]
            fn encrypt_tail_blocks(&self, blocks: InOutBuf<'_, '_, Block>) {
                let backend = self;

                let mut rem = blocks.len();
                let (mut iptr, mut optr) = blocks.into_raw();

                let backend = &$name_backend::Vaes256::from(backend);
                if backend.features.has_vaes256() {
                    while rem >= backend.par_blocks() {
                        let blocks = unsafe { InOut::from_raw(iptr.cast(), optr.cast()) };
                        backend.encrypt_par_blocks(blocks);
                        rem -= backend.par_blocks();
                        iptr = unsafe { iptr.add(backend.par_blocks()) };
                        optr = unsafe { optr.add(backend.par_blocks()) };
                    }
                }

                let backend = &$name_backend::Ni::from(backend);
                while rem >= backend.par_blocks() {
                    let blocks = unsafe { InOut::from_raw(iptr.cast(), optr.cast()) };
                    backend.encrypt_par_blocks(blocks);
                    rem -= backend.par_blocks();
                    iptr = unsafe { iptr.add(backend.par_blocks()) };
                    optr = unsafe { optr.add(backend.par_blocks()) };
                }

                while rem > 0 {
                    let block = unsafe { InOut::from_raw(iptr, optr) };
                    backend.encrypt_block(block);
                    rem -= 1;
                    iptr = unsafe { iptr.add(1) };
                    optr = unsafe { optr.add(1) };
                }
            }
        }

        impl<'a> BlockCipherDecBackend for $name_backend::Ni<'a> {
            #[inline]
            fn decrypt_block(&self, block: InOut<'_, '_, Block>) {
                unsafe {
                    self::ni::encdec::decrypt(self.keys, block);
                }
            }
            #[inline]
            fn decrypt_par_blocks(&self, blocks: InOut<'_, '_, cipher::ParBlocks<Self>>) {
                unsafe {
                    self::ni::encdec::decrypt_par(self.keys, blocks);
                }
            }
        }
        #[cfg(all(target_arch = "x86_64", any(aes_avx256, aes_avx512)))]
        impl<'a> BlockCipherDecBackend for $name_backend::Vaes256<'a> {
            #[inline]
            fn decrypt_block(&self, block: InOut<'_, '_, Block>) {
                unsafe {
                    self::ni::encdec::decrypt(self.keys, block);
                }
            }
            #[inline]
            fn decrypt_par_blocks(&self, blocks: InOut<'_, '_, cipher::ParBlocks<Self>>) {
                unsafe {
                    let simd_256_keys = self
                        .simd_256_keys
                        .get_or_init(|| vaes256::encdec::broadcast_keys(&self.keys));
                    vaes256::encdec::decrypt30(simd_256_keys, blocks);
                }
            }
            #[inline]
            fn decrypt_tail_blocks(&self, blocks: InOutBuf<'_, '_, Block>) {
                let backend = self;

                let mut rem = blocks.len();
                let (mut iptr, mut optr) = blocks.into_raw();

                let backend = $name_backend::Ni::from(backend);
                while rem >= backend.par_blocks() {
                    let blocks = unsafe { InOut::from_raw(iptr.cast(), optr.cast()) };
                    backend.decrypt_par_blocks(blocks);
                    rem -= backend.par_blocks();
                    iptr = unsafe { iptr.add(backend.par_blocks()) };
                    optr = unsafe { optr.add(backend.par_blocks()) };
                }

                while rem > 0 {
                    let block = unsafe { InOut::from_raw(iptr, optr) };
                    backend.decrypt_block(block);
                    rem -= 1;
                    iptr = unsafe { iptr.add(1) };
                    optr = unsafe { optr.add(1) };
                }
            }
        }
        #[cfg(all(target_arch = "x86_64", aes_avx512))]
        impl<'a> BlockCipherDecBackend for $name_backend::Vaes512<'a> {
            #[inline]
            fn decrypt_block(&self, block: InOut<'_, '_, Block>) {
                unsafe {
                    self::ni::encdec::decrypt(self.keys, block);
                }
            }
            #[inline]
            fn decrypt_par_blocks(&self, blocks: InOut<'_, '_, cipher::ParBlocks<Self>>) {
                unsafe {
                    let simd_512_keys = self
                        .simd_512_keys
                        .get_or_init(|| vaes512::encdec::broadcast_keys(&self.keys));
                    vaes512::encdec::decrypt64(simd_512_keys, blocks);
                }
            }
            #[inline]
            fn decrypt_tail_blocks(&self, blocks: InOutBuf<'_, '_, Block>) {
                let backend = self;

                let mut rem = blocks.len();
                let (mut iptr, mut optr) = blocks.into_raw();

                let backend = &$name_backend::Vaes256::from(backend);
                if backend.features.has_vaes256() {
                    while rem >= backend.par_blocks() {
                        let blocks = unsafe { InOut::from_raw(iptr.cast(), optr.cast()) };
                        backend.decrypt_par_blocks(blocks);
                        rem -= backend.par_blocks();
                        iptr = unsafe { iptr.add(backend.par_blocks()) };
                        optr = unsafe { optr.add(backend.par_blocks()) };
                    }
                }

                let backend = &$name_backend::Ni::from(backend);
                while rem >= backend.par_blocks() {
                    let blocks = unsafe { InOut::from_raw(iptr.cast(), optr.cast()) };
                    backend.decrypt_par_blocks(blocks);
                    rem -= backend.par_blocks();
                    iptr = unsafe { iptr.add(backend.par_blocks()) };
                    optr = unsafe { optr.add(backend.par_blocks()) };
                }

                while rem > 0 {
                    let block = unsafe { InOut::from_raw(iptr, optr) };
                    backend.decrypt_block(block);
                    rem -= 1;
                    iptr = unsafe { iptr.add(1) };
                    optr = unsafe { optr.add(1) };
                }
            }
        }
    };
}

define_aes_impl!(
    Aes128,
    Aes128Enc,
    Aes128Dec,
    aes128_backend,
    aes128,
    U16,
    11,
    "AES-128",
);

define_aes_impl!(
    Aes192,
    Aes192Enc,
    Aes192Dec,
    aes192_backend,
    aes192,
    U24,
    13,
    "AES-192",
);

define_aes_impl!(
    Aes256,
    Aes256Enc,
    Aes256Dec,
    aes256_backend,
    aes256,
    U32,
    15,
    "AES-256",
);
