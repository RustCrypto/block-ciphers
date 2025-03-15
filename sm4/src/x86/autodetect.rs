//! SM4 X86

#![allow(unsafe_code)]

use cipher::{
    AlgorithmName, BlockCipherDecClosure, BlockCipherDecrypt, BlockCipherEncClosure,
    BlockCipherEncrypt, BlockSizeUser, Key, KeyInit, KeySizeUser, ParBlocksSizeUser,
    consts::{U1, U16},
};
use core::{fmt, mem::ManuallyDrop};

cpufeatures::new!(aes_intrinsics, "aes");
cpufeatures::new!(avx2_intrinsics, "avx2");

union Sm4Cipher {
    avx2: ManuallyDrop<super::avx2::Sm4>,
    aesni: ManuallyDrop<super::aesni::Sm4>,
    soft: ManuallyDrop<crate::soft::Sm4>,
}

/// SM4 block cipher.
pub struct Sm4 {
    cipher: Sm4Cipher,
    aes_token: aes_intrinsics::InitToken,
    avx2_token: avx2_intrinsics::InitToken,
}

impl KeySizeUser for Sm4 {
    type KeySize = U16;
}

impl KeyInit for Sm4 {
    #[inline]
    fn new(key: &Key<Self>) -> Self {
        let (aes_token, aes_presence) = aes_intrinsics::init_get();
        let (avx2_token, avx2_presence) = avx2_intrinsics::init_get();

        let cipher = if aes_presence {
            Sm4Cipher {
                aesni: ManuallyDrop::new(super::aesni::Sm4::new(key)),
            }
        } else if avx2_presence {
            Sm4Cipher {
                avx2: ManuallyDrop::new(super::avx2::Sm4::new(key)),
            }
        } else {
            Sm4Cipher {
                soft: ManuallyDrop::new(crate::soft::Sm4::new(key)),
            }
        };

        Self {
            cipher,
            aes_token,
            avx2_token,
        }
    }
}

impl Clone for Sm4 {
    fn clone(&self) -> Self {
        let cipher = if self.aes_token.get() {
            Sm4Cipher {
                aesni: unsafe { self.cipher.aesni.clone() },
            }
        } else if self.avx2_token.get() {
            Sm4Cipher {
                avx2: unsafe { self.cipher.avx2.clone() },
            }
        } else {
            Sm4Cipher {
                soft: unsafe { self.cipher.soft.clone() },
            }
        };

        Self {
            cipher,
            aes_token: self.aes_token,
            avx2_token: self.avx2_token,
        }
    }
}

impl BlockSizeUser for Sm4 {
    type BlockSize = U16;
}

impl ParBlocksSizeUser for Sm4 {
    type ParBlocksSize = U1;
}

impl BlockCipherEncrypt for Sm4 {
    #[inline]
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
        unsafe {
            if self.aes_token.get() {
                self.cipher.aesni.encrypt_with_backend(f);
            } else if self.avx2_token.get() {
                self.cipher.avx2.encrypt_with_backend(f);
            } else {
                self.cipher.soft.encrypt_with_backend(f);
            }
        }
    }
}

impl BlockCipherDecrypt for Sm4 {
    #[inline]
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
        unsafe {
            if self.aes_token.get() {
                self.cipher.aesni.decrypt_with_backend(f);
            } else if self.avx2_token.get() {
                self.cipher.avx2.decrypt_with_backend(f);
            } else {
                self.cipher.soft.decrypt_with_backend(f);
            }
        }
    }
}

impl fmt::Debug for Sm4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(concat!(stringify!(Sm4), " { .. }"))
    }
}

impl AlgorithmName for Sm4 {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(stringify!(Sm4))
    }
}

impl Drop for Sm4 {
    fn drop(&mut self) {
        if self.aes_token.get() {
            unsafe { ManuallyDrop::drop(&mut self.cipher.aesni) }
        } else if self.avx2_token.get() {
            unsafe { ManuallyDrop::drop(&mut self.cipher.avx2) }
        } else {
            unsafe { ManuallyDrop::drop(&mut self.cipher.soft) }
        }
    }
}
