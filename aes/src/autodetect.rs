//! Autodetection support for hardware accelerated AES backends with fallback
//! to the fixsliced "soft" implementation.

use crate::{Block, ParBlocks};
use cipher::{
    consts::{U16, U24, U32, U8},
    generic_array::GenericArray,
    BlockCipher, BlockDecrypt, BlockEncrypt, NewBlockCipher,
};
use core::mem::ManuallyDrop;

cpuid_bool::new!(aes_cpuid, "aes");

macro_rules! define_aes_impl {
    (
        $name:tt,
        $module:tt,
        $key_size:ty,
        $doc:expr
    ) => {
        #[doc=$doc]
        pub struct $name {
            inner: $module::Inner,
            token: aes_cpuid::InitToken
        }

        mod $module {
            use core::mem::ManuallyDrop;

            pub(super) union Inner {
                pub(super) ni: ManuallyDrop<crate::ni::$name>,
                pub(super) soft: ManuallyDrop<crate::soft::$name>,
            }
        }

        impl NewBlockCipher for $name {
            type KeySize = $key_size;

            #[inline]
            fn new(key: &GenericArray<u8, $key_size>) -> Self {
                let (token, aesni_present) = aes_cpuid::init_get();

                let inner = if aesni_present {
                    $module::Inner { ni: ManuallyDrop::new(crate::ni::$name::new(key)) }
                } else {
                    $module::Inner { soft: ManuallyDrop::new(crate::soft::$name::new(key)) }
                };

                Self { inner, token }
            }
        }

        impl Clone for $name {
            fn clone(&self) -> Self {
                let inner = if self.token.get() {
                    $module::Inner { ni: unsafe { self.inner.ni.clone() } }
                } else {
                    $module::Inner { soft: unsafe { self.inner.soft.clone() } }
                };

                Self { inner, token: self.token }
            }
        }

        impl BlockCipher for $name {
            type BlockSize = U16;
            type ParBlocks = U8;
        }

        impl BlockEncrypt for $name {
            #[inline]
            fn encrypt_block(&self, block: &mut Block) {
                if self.token.get() {
                    unsafe { self.inner.ni.encrypt_block(block) }
                } else {
                    unsafe { self.inner.soft.encrypt_block(block) }
                }
            }

            #[inline]
            fn encrypt_par_blocks(&self, blocks: &mut ParBlocks) {
                if self.token.get() {
                    unsafe { self.inner.ni.encrypt_par_blocks(blocks) }
                } else {
                    unsafe { self.inner.soft.encrypt_par_blocks(blocks) }
                }
            }
        }

        impl BlockDecrypt for $name {
            #[inline]
            fn decrypt_block(&self, block: &mut Block) {
                if self.token.get() {
                    unsafe { self.inner.ni.decrypt_block(block) }
                } else {
                    unsafe { self.inner.soft.decrypt_block(block) }
                }
            }

            #[inline]
            fn decrypt_par_blocks(&self, blocks: &mut ParBlocks) {
                if self.token.get() {
                    unsafe { self.inner.ni.decrypt_par_blocks(blocks) }
                } else {
                    unsafe { self.inner.soft.decrypt_par_blocks(blocks) }
                }
            }
        }

        opaque_debug::implement!($name);
    }
}

define_aes_impl!(Aes128, aes128, U16, "AES-128 block cipher instance");
define_aes_impl!(Aes192, aes192, U24, "AES-192 block cipher instance");
define_aes_impl!(Aes256, aes256, U32, "AES-256 block cipher instance");

#[cfg(feature = "ctr")]
pub(crate) mod ctr {
    use super::{Aes128, Aes192, Aes256};
    use cipher::{
        errors::{LoopError, OverflowError},
        generic_array::GenericArray,
        BlockCipher, FromBlockCipher, SeekNum, StreamCipher, StreamCipherSeek,
    };
    use core::mem::ManuallyDrop;

    cpuid_bool::new!(aes_ssse3_cpuid, "aes", "ssse3");

    macro_rules! define_aes_ctr_impl {
        (
            $name:tt,
            $cipher:ident,
            $module:tt,
            $doc:expr
        ) => {
            #[doc=$doc]
            #[cfg_attr(docsrs, doc(cfg(feature = "ctr")))]
            pub struct $name {
                inner: $module::Inner,
                token: aes_ssse3_cpuid::InitToken
            }

            mod $module {
                use core::mem::ManuallyDrop;

                pub(super) union Inner {
                    pub(super) ni: ManuallyDrop<crate::ni::$name>,
                    pub(super) soft: ManuallyDrop<crate::soft::$name>,
                }
            }

            impl FromBlockCipher for $name {
                type BlockCipher = $cipher;
                type NonceSize = <$cipher as BlockCipher>::BlockSize;

                fn from_block_cipher(
                    cipher: $cipher,
                    nonce: &GenericArray<u8, Self::NonceSize>,
                ) -> Self {
                    let (token, aesni_present) = aes_ssse3_cpuid::init_get();

                    let inner = if aesni_present {
                        let ni = crate::ni::$name::from_block_cipher(
                            unsafe { (*cipher.inner.ni).clone() },
                            nonce
                        );

                        $module::Inner { ni: ManuallyDrop::new(ni) }
                    } else {
                        let soft = crate::soft::$name::from_block_cipher(
                            unsafe { (*cipher.inner.soft).clone() },
                            nonce
                        );

                        $module::Inner { soft: ManuallyDrop::new(soft) }
                    };

                    Self { inner, token }
                }
            }

            impl StreamCipher for $name {
                #[inline]
                fn try_apply_keystream(&mut self, data: &mut [u8]) -> Result<(), LoopError> {
                    if self.token.get() {
                        unsafe { (*self.inner.ni).try_apply_keystream(data) }
                    } else {
                        unsafe { (*self.inner.soft).try_apply_keystream(data) }
                    }
                }
            }

            impl StreamCipherSeek for $name {
                #[inline]
                fn try_current_pos<T: SeekNum>(&self) -> Result<T, OverflowError> {
                    if self.token.get() {
                        unsafe { (*self.inner.ni).try_current_pos() }
                    } else {
                        unsafe { (*self.inner.soft).try_current_pos() }
                    }
                }

                #[inline]
                fn try_seek<T: SeekNum>(&mut self, pos: T) -> Result<(), LoopError> {
                    if self.token.get() {
                        unsafe { (*self.inner.ni).try_seek(pos) }
                    } else {
                        unsafe { (*self.inner.soft).try_seek(pos) }
                    }
                }
            }

            opaque_debug::implement!($name);
        }
    }

    define_aes_ctr_impl!(Aes128Ctr, Aes128, aes128ctr, "AES-128 in CTR mode");
    define_aes_ctr_impl!(Aes192Ctr, Aes192, aes192ctr, "AES-192 in CTR mode");
    define_aes_ctr_impl!(Aes256Ctr, Aes256, aes256ctr, "AES-256 in CTR mode");
}
