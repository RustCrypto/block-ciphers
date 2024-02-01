//! Autodetection support for hardware accelerated AES backends with fallback
//! to the fixsliced "soft" implementation.

use crate::soft;
use cipher::{
    consts::{U16, U24, U32},
    AlgorithmName, BlockCipher, BlockCipherDecrypt, BlockCipherEncrypt, BlockClosure,
    BlockSizeUser, Key, KeyInit, KeySizeUser,
};
use core::fmt;
use core::mem::ManuallyDrop;

#[cfg(target_arch = "aarch64")]
use crate::armv8 as arch;

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
use crate::x86 as arch;

macro_rules! define_aes_impl {
    (
        $name:ident,
        $name_enc:ident,
        $name_dec:ident,
        $module:tt,
        $key_size:ty,
        $doc:expr $(,)?
    ) => {
        mod $module {
            use super::{arch, soft};
            use core::mem::ManuallyDrop;

            pub(super) union Inner {
                pub(super) arch: ManuallyDrop<arch::$name>,
                pub(super) soft: ManuallyDrop<soft::$name>,
            }

            pub(super) union InnerEnc {
                pub(super) arch: ManuallyDrop<arch::$name_enc>,
                pub(super) soft: ManuallyDrop<soft::$name_enc>,
            }

            pub(super) union InnerDec {
                pub(super) arch: ManuallyDrop<arch::$name_dec>,
                pub(super) soft: ManuallyDrop<soft::$name_dec>,
            }
        }

        #[doc=$doc]
        #[doc = "block cipher"]
        pub struct $name {
            inner: $module::Inner,
            token: arch::features::aes::InitToken,
        }

        impl KeySizeUser for $name {
            type KeySize = $key_size;
        }
        impl From<$name_enc> for $name {
            #[inline]
            fn from(enc: $name_enc) -> $name {
                Self::from(&enc)
            }
        }

        impl From<&$name_enc> for $name {
            fn from(enc: &$name_enc) -> $name {
                use core::ops::Deref;
                let inner = if enc.token.get() {
                    $module::Inner {
                        arch: ManuallyDrop::new(unsafe { enc.inner.arch.deref().into() }),
                    }
                } else {
                    $module::Inner {
                        soft: ManuallyDrop::new(unsafe { enc.inner.soft.deref().into() }),
                    }
                };

                Self {
                    inner,
                    token: enc.token,
                }
            }
        }

        impl KeyInit for $name {
            #[inline]
            fn new(key: &Key<Self>) -> Self {
                let (token, aes_features) = arch::features::aes::init_get();

                let inner = if aes_features {
                    $module::Inner {
                        arch: ManuallyDrop::new(arch::$name::new(key)),
                    }
                } else {
                    $module::Inner {
                        soft: ManuallyDrop::new(soft::$name::new(key)),
                    }
                };

                Self { inner, token }
            }
        }

        impl Clone for $name {
            fn clone(&self) -> Self {
                let inner = if self.token.get() {
                    $module::Inner {
                        arch: unsafe { self.inner.arch.clone() },
                    }
                } else {
                    $module::Inner {
                        soft: unsafe { self.inner.soft.clone() },
                    }
                };

                Self {
                    inner,
                    token: self.token,
                }
            }
        }

        impl BlockSizeUser for $name {
            type BlockSize = U16;
        }

        impl BlockCipher for $name {}

        impl BlockCipherEncrypt for $name {
            fn encrypt_with_backend(&self, f: impl BlockClosure<BlockSize = U16>) {
                if self.token.get() {
                    unsafe { &self.inner.arch }.encrypt_with_backend(f)
                } else {
                    unsafe { &self.inner.soft }.encrypt_with_backend(f)
                }
            }
        }

        impl BlockCipherDecrypt for $name {
            fn decrypt_with_backend(&self, f: impl BlockClosure<BlockSize = U16>) {
                if self.token.get() {
                    unsafe { &self.inner.arch }.decrypt_with_backend(f)
                } else {
                    unsafe { &self.inner.soft }.decrypt_with_backend(f)
                }
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

        impl Drop for $name {
            #[inline]
            fn drop(&mut self) {
                if self.token.get() {
                    unsafe { ManuallyDrop::drop(&mut self.inner.arch) };
                } else {
                    unsafe { ManuallyDrop::drop(&mut self.inner.soft) };
                };
            }
        }

        #[cfg(feature = "zeroize")]
        impl zeroize::ZeroizeOnDrop for $name {}

        #[doc=$doc]
        #[doc = "block cipher (encrypt-only)"]
        pub struct $name_enc {
            inner: $module::InnerEnc,
            token: arch::features::aes::InitToken,
        }

        impl KeySizeUser for $name_enc {
            type KeySize = $key_size;
        }

        impl KeyInit for $name_enc {
            #[inline]
            fn new(key: &Key<Self>) -> Self {
                let (token, aes_features) = arch::features::aes::init_get();

                let inner = if aes_features {
                    $module::InnerEnc {
                        arch: ManuallyDrop::new(arch::$name_enc::new(key)),
                    }
                } else {
                    $module::InnerEnc {
                        soft: ManuallyDrop::new(soft::$name_enc::new(key)),
                    }
                };

                Self { inner, token }
            }
        }

        impl Clone for $name_enc {
            fn clone(&self) -> Self {
                let inner = if self.token.get() {
                    $module::InnerEnc {
                        arch: unsafe { self.inner.arch.clone() },
                    }
                } else {
                    $module::InnerEnc {
                        soft: unsafe { self.inner.soft.clone() },
                    }
                };

                Self {
                    inner,
                    token: self.token,
                }
            }
        }

        impl BlockSizeUser for $name_enc {
            type BlockSize = U16;
        }

        impl BlockCipher for $name_enc {}

        impl BlockCipherEncrypt for $name_enc {
            fn encrypt_with_backend(&self, f: impl BlockClosure<BlockSize = U16>) {
                if self.token.get() {
                    unsafe { &self.inner.arch }.encrypt_with_backend(f)
                } else {
                    unsafe { &self.inner.soft }.encrypt_with_backend(f)
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

        impl Drop for $name_enc {
            #[inline]
            fn drop(&mut self) {
                if self.token.get() {
                    unsafe { ManuallyDrop::drop(&mut self.inner.arch) };
                } else {
                    unsafe { ManuallyDrop::drop(&mut self.inner.soft) };
                };
            }
        }

        #[cfg(feature = "zeroize")]
        impl zeroize::ZeroizeOnDrop for $name_enc {}

        #[doc=$doc]
        #[doc = "block cipher (decrypt-only)"]
        pub struct $name_dec {
            inner: $module::InnerDec,
            token: arch::features::aes::InitToken,
        }

        impl KeySizeUser for $name_dec {
            type KeySize = $key_size;
        }

        impl From<$name_enc> for $name_dec {
            #[inline]
            fn from(enc: $name_enc) -> $name_dec {
                Self::from(&enc)
            }
        }

        impl From<&$name_enc> for $name_dec {
            fn from(enc: &$name_enc) -> $name_dec {
                use core::ops::Deref;
                let inner = if enc.token.get() {
                    $module::InnerDec {
                        arch: ManuallyDrop::new(unsafe { enc.inner.arch.deref().into() }),
                    }
                } else {
                    $module::InnerDec {
                        soft: ManuallyDrop::new(unsafe { enc.inner.soft.deref().into() }),
                    }
                };

                Self {
                    inner,
                    token: enc.token,
                }
            }
        }

        impl KeyInit for $name_dec {
            #[inline]
            fn new(key: &Key<Self>) -> Self {
                let (token, aes_features) = arch::features::aes::init_get();

                let inner = if aes_features {
                    $module::InnerDec {
                        arch: ManuallyDrop::new(arch::$name_dec::new(key)),
                    }
                } else {
                    $module::InnerDec {
                        soft: ManuallyDrop::new(soft::$name_dec::new(key)),
                    }
                };

                Self { inner, token }
            }
        }

        impl Clone for $name_dec {
            fn clone(&self) -> Self {
                let inner = if self.token.get() {
                    $module::InnerDec {
                        arch: unsafe { self.inner.arch.clone() },
                    }
                } else {
                    $module::InnerDec {
                        soft: unsafe { self.inner.soft.clone() },
                    }
                };

                Self {
                    inner,
                    token: self.token,
                }
            }
        }

        impl BlockSizeUser for $name_dec {
            type BlockSize = U16;
        }

        impl BlockCipher for $name_dec {}

        impl BlockCipherDecrypt for $name_dec {
            fn decrypt_with_backend(&self, f: impl BlockClosure<BlockSize = U16>) {
                if self.token.get() {
                    unsafe { &self.inner.arch }.decrypt_with_backend(f)
                } else {
                    unsafe { &self.inner.soft }.decrypt_with_backend(f)
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

        impl Drop for $name_dec {
            #[inline]
            fn drop(&mut self) {
                if self.token.get() {
                    unsafe { ManuallyDrop::drop(&mut self.inner.arch) };
                } else {
                    unsafe { ManuallyDrop::drop(&mut self.inner.soft) };
                };
            }
        }

        #[cfg(feature = "zeroize")]
        impl zeroize::ZeroizeOnDrop for $name_dec {}
    };
}

define_aes_impl!(Aes128, Aes128Enc, Aes128Dec, aes128, U16, "AES-128");
define_aes_impl!(Aes192, Aes192Enc, Aes192Dec, aes192, U24, "AES-192");
define_aes_impl!(Aes256, Aes256Enc, Aes256Dec, aes256, U32, "AES-256");
