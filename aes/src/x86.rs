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
use crate::{Block, Block8};
#[cfg(target_arch = "x86_64")]
use crate::{Block30, Block64};
#[cfg(target_arch = "x86_64")]
use cipher::consts::{U30, U64};
use cipher::{
    consts::{U16, U24, U32, U8},
    inout::InOut,
    AlgorithmName, BlockBackend, BlockCipher, BlockCipherDecrypt, BlockCipherEncrypt, BlockClosure,
    BlockSizeUser, Key, KeyInit, KeySizeUser, ParBlocksSizeUser,
};
use core::fmt;

pub(crate) mod features {
    cpufeatures::new!(features_aes, "aes");
    cpufeatures::new!(features_avx, "avx");
    cpufeatures::new!(features_avx512f, "avx512f");
    cpufeatures::new!(features_vaes, "vaes");
    pub(crate) mod aes {
        pub use super::features_aes::*;
    }
    #[cfg(target_arch = "x86_64")]
    pub(crate) mod avx {
        pub use super::features_avx::*;
    }
    #[cfg(target_arch = "x86_64")]
    pub(crate) mod avx512f {
        pub use super::features_avx512f::*;
    }
    #[cfg(target_arch = "x86_64")]
    pub(crate) mod vaes {
        pub use super::features_vaes::*;
    }
}

#[derive(Clone)]
enum Backend {
    Ni,
    #[cfg(target_arch = "x86_64")]
    Vaes256,
    #[cfg(target_arch = "x86_64")]
    Vaes512,
}

#[derive(Clone)]
struct Features {
    #[cfg(target_arch = "x86_64")]
    avx: self::features::avx::InitToken,
    #[cfg(target_arch = "x86_64")]
    avx512f: self::features::avx512f::InitToken,
    #[cfg(target_arch = "x86_64")]
    vaes: self::features::vaes::InitToken,
}

impl Features {
    fn new() -> Self {
        Self {
            #[cfg(target_arch = "x86_64")]
            avx: self::features::avx::init(),
            #[cfg(target_arch = "x86_64")]
            avx512f: self::features::avx512f::init(),
            #[cfg(target_arch = "x86_64")]
            vaes: self::features::vaes::init(),
        }
    }

    fn backend(&self) -> Backend {
        #[allow(unused_mut)]
        let mut backend = Backend::Ni;
        #[cfg(target_arch = "x86_64")]
        if !cfg!(disable_avx512) && self.avx512f.get() && self.vaes.get() {
            backend = self::Backend::Vaes512;
        }
        #[cfg(target_arch = "x86_64")]
        if !cfg!(disable_avx256) && self.avx.get() && self.vaes.get() {
            backend = self::Backend::Vaes256;
        }
        backend
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
        $name_backend:ident,
        $module:tt,
        $key_size:ty,
        $rounds:tt,
        $doc:expr $(,)?
    ) => {
        mod $name_backend {
            use super::*;
            pub(crate) mod mode {
                pub(crate) struct Encrypt;
                pub(crate) struct Decrypt;
            }
            #[derive(Clone)]
            pub(crate) struct Ni<'a, Mode> {
                pub(crate) mode: core::marker::PhantomData<Mode>,
                pub(crate) keys: &'a RoundKeys<$rounds>,
            }
            #[derive(Clone)]
            #[cfg(target_arch = "x86_64")]
            pub(crate) struct Vaes256<'a, Mode> {
                pub(crate) mode: core::marker::PhantomData<Mode>,
                pub(crate) keys: &'a RoundKeys<$rounds>,
                pub(crate) simd_256_keys: Option<Simd256RoundKeys<$rounds>>,
            }
            #[cfg(target_arch = "x86_64")]
            pub(crate) struct Vaes512<'a, Mode> {
                pub(crate) mode: core::marker::PhantomData<Mode>,
                pub(crate) keys: &'a RoundKeys<$rounds>,
                pub(crate) simd_512_keys: Option<Simd512RoundKeys<$rounds>>,
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

        #[doc=$doc]
        #[doc = "block cipher (encrypt-only)"]
        #[derive(Clone)]
        pub struct $name_enc {
            round_keys: RoundKeys<$rounds>,
            features: Features,
        }

        impl Drop for $name_enc {
            fn drop(&mut self) {
                #[cfg(feature = "zeroize")]
                zeroize::Zeroize::zeroize(&mut self.round_keys);
            }
        }
        #[cfg(feature = "zeroize")]
        impl zeroize::ZeroizeOnDrop for $name_enc {}

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
                    features: Features::new(),
                }
            }
        }

        impl BlockSizeUser for $name_enc {
            type BlockSize = U16;
        }

        impl BlockCipherEncrypt for $name_enc {
            #[inline]
            fn encrypt_with_backend(&self, f: impl BlockClosure<BlockSize = U16>) {
                let mode = core::marker::PhantomData::<self::$name_backend::mode::Encrypt>;
                let keys = &self.round_keys;
                match self.features.backend() {
                    self::Backend::Ni => f.call(&mut $name_backend::Ni { mode, keys }),
                    #[cfg(target_arch = "x86_64")]
                    self::Backend::Vaes256 => f.call(&mut $name_backend::Vaes256 {
                        mode,
                        keys,
                        simd_256_keys: None,
                    }),
                    #[cfg(target_arch = "x86_64")]
                    self::Backend::Vaes512 => f.call(&mut $name_backend::Vaes512 {
                        mode,
                        keys,
                        simd_512_keys: None,
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
            round_keys: RoundKeys<$rounds>,
            features: Features,
        }

        impl Drop for $name_dec {
            fn drop(&mut self) {
                #[cfg(feature = "zeroize")]
                zeroize::Zeroize::zeroize(&mut self.round_keys);
            }
        }

        impl BlockCipher for $name_dec {}
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
                    round_keys: unsafe { self::ni::$module::inv_expanded_keys(&enc.round_keys) },
                    features: enc.features.clone(),
                }
            }
        }

        impl BlockSizeUser for $name_dec {
            type BlockSize = U16;
        }

        impl BlockCipherDecrypt for $name_dec {
            #[inline]
            fn decrypt_with_backend(&self, f: impl BlockClosure<BlockSize = U16>) {
                let mode = core::marker::PhantomData::<self::$name_backend::mode::Decrypt>;
                let keys = &self.round_keys;
                match self.features.backend() {
                    self::Backend::Ni => f.call(&mut $name_backend::Ni { mode, keys }),
                    #[cfg(target_arch = "x86_64")]
                    self::Backend::Vaes256 => f.call(&mut $name_backend::Vaes256 {
                        mode,
                        keys,
                        simd_256_keys: None,
                    }),
                    #[cfg(target_arch = "x86_64")]
                    self::Backend::Vaes512 => f.call(&mut $name_backend::Vaes512 {
                        mode,
                        keys,
                        simd_512_keys: None,
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

        impl<'a, Mode> BlockSizeUser for $name_backend::Ni<'a, Mode> {
            type BlockSize = U16;
        }
        #[cfg(target_arch = "x86_64")]
        impl<'a, Mode> BlockSizeUser for $name_backend::Vaes256<'a, Mode> {
            type BlockSize = U16;
        }
        #[cfg(target_arch = "x86_64")]
        impl<'a, Mode> BlockSizeUser for $name_backend::Vaes512<'a, Mode> {
            type BlockSize = U16;
        }

        impl<'a, Mode> ParBlocksSizeUser for $name_backend::Ni<'a, Mode> {
            type ParBlocksSize = U8;
        }
        #[cfg(target_arch = "x86_64")]
        impl<'a, Mode> ParBlocksSizeUser for $name_backend::Vaes256<'a, Mode> {
            type ParBlocksSize = U30;
        }
        #[cfg(target_arch = "x86_64")]
        impl<'a, Mode> ParBlocksSizeUser for $name_backend::Vaes512<'a, Mode> {
            type ParBlocksSize = U64;
        }

        impl<'a> BlockBackend for $name_backend::Ni<'a, self::$name_backend::mode::Encrypt> {
            #[inline]
            fn proc_block(&mut self, block: InOut<'_, '_, Block>) {
                unsafe {
                    self::ni::$module::encrypt1(self.keys, block);
                }
            }
            #[inline]
            fn proc_par_blocks(&mut self, blocks: InOut<'_, '_, Block8>) {
                unsafe {
                    self::ni::$module::encrypt8(self.keys, blocks);
                }
            }
        }
        #[cfg(target_arch = "x86_64")]
        impl<'a> BlockBackend for $name_backend::Vaes256<'a, self::$name_backend::mode::Encrypt> {
            #[inline]
            fn proc_block(&mut self, block: InOut<'_, '_, Block>) {
                unsafe {
                    self::ni::$module::encrypt1(self.keys, block);
                }
            }
            #[inline]
            fn proc_par_blocks(&mut self, blocks: InOut<'_, '_, Block30>) {
                unsafe {
                    let simd_256_keys = self.simd_256_keys.get_or_insert_with(|| {
                        self::vaes256::$module::parallelize_keys(&self.keys)
                    });
                    self::vaes256::$module::encrypt30(simd_256_keys, blocks);
                }
            }
        }
        #[cfg(target_arch = "x86_64")]
        impl<'a> BlockBackend for $name_backend::Vaes512<'a, self::$name_backend::mode::Encrypt> {
            #[inline]
            fn proc_block(&mut self, block: InOut<'_, '_, Block>) {
                unsafe {
                    self::ni::$module::encrypt1(self.keys, block);
                }
            }
            #[inline]
            fn proc_par_blocks(&mut self, blocks: InOut<'_, '_, Block64>) {
                unsafe {
                    let simd_512_keys = self.simd_512_keys.get_or_insert_with(|| {
                        self::vaes512::$module::parallelize_keys(&self.keys)
                    });
                    self::vaes512::$module::encrypt64(simd_512_keys, blocks);
                }
            }
        }

        impl<'a> BlockBackend for $name_backend::Ni<'a, self::$name_backend::mode::Decrypt> {
            #[inline]
            fn proc_block(&mut self, block: InOut<'_, '_, Block>) {
                unsafe {
                    self::ni::$module::decrypt1(self.keys, block);
                }
            }
            #[inline]
            fn proc_par_blocks(&mut self, blocks: InOut<'_, '_, Block8>) {
                unsafe {
                    self::ni::$module::decrypt8(self.keys, blocks);
                }
            }
        }
        #[cfg(target_arch = "x86_64")]
        impl<'a> BlockBackend for $name_backend::Vaes256<'a, self::$name_backend::mode::Decrypt> {
            #[inline]
            fn proc_block(&mut self, block: InOut<'_, '_, Block>) {
                unsafe {
                    self::ni::$module::decrypt1(self.keys, block);
                }
            }
            #[inline]
            fn proc_par_blocks(&mut self, blocks: InOut<'_, '_, Block30>) {
                unsafe {
                    let simd_256_keys = self.simd_256_keys.get_or_insert_with(|| {
                        self::vaes256::$module::parallelize_keys(&self.keys)
                    });
                    self::vaes256::$module::decrypt30(simd_256_keys, blocks);
                }
            }
        }
        #[cfg(target_arch = "x86_64")]
        impl<'a> BlockBackend for $name_backend::Vaes512<'a, self::$name_backend::mode::Decrypt> {
            #[inline]
            fn proc_block(&mut self, block: InOut<'_, '_, Block>) {
                unsafe {
                    self::ni::$module::decrypt1(self.keys, block);
                }
            }
            #[inline]
            fn proc_par_blocks(&mut self, blocks: InOut<'_, '_, Block64>) {
                unsafe {
                    let simd_512_keys = self.simd_512_keys.get_or_insert_with(|| {
                        self::vaes512::$module::parallelize_keys(&self.keys)
                    });
                    self::vaes512::$module::decrypt64(simd_512_keys, blocks);
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
