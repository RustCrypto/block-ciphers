#![allow(unsafe_code)]

use cipher::{
    consts::U16, AlgorithmName, BlockCipher, BlockClosure, BlockDecrypt, BlockEncrypt,
    BlockSizeUser, Key, KeyInit, KeySizeUser,
};
use core::{fmt, mem::ManuallyDrop};

use crate::armv8::{neon::Sm4 as NeonSm4, sm4e::Sm4 as CryptoExtensionSm4};

cpufeatures::new!(sm4_intrinsics, "sm4");

union Sm4Cipher {
    sm4: ManuallyDrop<CryptoExtensionSm4>,
    neon: ManuallyDrop<NeonSm4>,
}

/// SM4 block cipher.
pub struct Sm4 {
    cipher: Sm4Cipher,
    token: sm4_intrinsics::InitToken,
}

impl KeySizeUser for Sm4 {
    type KeySize = U16;
}

impl KeyInit for Sm4 {
    #[inline]
    fn new(key: &Key<Self>) -> Self {
        let (token, intrinsics_presense) = sm4_intrinsics::init_get();

        let cipher = if intrinsics_presense {
            Sm4Cipher {
                sm4: ManuallyDrop::new(CryptoExtensionSm4::new(key)),
            }
        } else {
            Sm4Cipher {
                neon: ManuallyDrop::new(NeonSm4::new(key)),
            }
        };

        Self { cipher, token }
    }
}

impl Clone for Sm4 {
    fn clone(&self) -> Self {
        let cipher = if self.token.get() {
            Sm4Cipher {
                sm4: unsafe { self.cipher.sm4.clone() },
            }
        } else {
            Sm4Cipher {
                neon: unsafe { self.cipher.neon.clone() },
            }
        };

        Self {
            cipher,
            token: self.token,
        }
    }
}

impl BlockSizeUser for Sm4 {
    type BlockSize = U16;
}

impl BlockCipher for Sm4 {}

impl BlockEncrypt for Sm4 {
    fn encrypt_with_backend(&self, f: impl BlockClosure<BlockSize = U16>) {
        unsafe {
            if self.token.get() {
                self.cipher.sm4.encrypt_with_backend(f);
            } else {
                self.cipher.neon.encrypt_with_backend(f);
            }
        }
    }
}

impl BlockDecrypt for Sm4 {
    fn decrypt_with_backend(&self, f: impl BlockClosure<BlockSize = U16>) {
        unsafe {
            if self.token.get() {
                self.cipher.sm4.decrypt_with_backend(f);
            } else {
                self.cipher.neon.decrypt_with_backend(f);
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
        #[allow(unsafe_code)]
        if self.token.get() {
            unsafe { ManuallyDrop::drop(&mut self.cipher.sm4) }
        } else {
            unsafe { ManuallyDrop::drop(&mut self.cipher.neon) }
        }
    }
}
