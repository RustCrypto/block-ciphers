//! [Cipher Feedback with eight bit feedback][1] (CFB-8) mode.
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CFB-1,_CFB-8,_CFB-64,_CFB-128,_etc.

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

use cipher::{
    generic_array::{typenum::U1, GenericArray},
    AsyncStreamCipher, Block, BlockCipher, BlockDecryptMut, BlockEncryptMut, BlockProcessing,
    InOutVal, InnerIvInit, IvState,
};

/// CFB-8 mode encryptor.
#[derive(Clone)]
pub struct Encrypt<C: BlockEncryptMut + BlockCipher> {
    cipher: C,
    iv: Block<C>,
}

impl<C: BlockEncryptMut + BlockCipher> BlockEncryptMut for Encrypt<C> {
    fn encrypt_block(&mut self, mut block: impl InOutVal<Block<Self>>) {
        let mut t = self.iv.clone();
        self.cipher.encrypt_block(&mut t);
        let r = block.get_in()[0] ^ t[0];
        block.get_out()[0] = r;
        let n = self.iv.len();
        for i in 0..n - 1 {
            self.iv[i] = self.iv[i + 1];
        }
        self.iv[n - 1] = r;
    }
}

impl<C: BlockEncryptMut + BlockCipher> BlockProcessing for Encrypt<C> {
    type BlockSize = U1;
}

impl<C: BlockEncryptMut + BlockCipher> AsyncStreamCipher for Encrypt<C> {}

impl<C: BlockEncryptMut + BlockCipher> InnerIvInit for Encrypt<C> {
    type Inner = C;
    type IvSize = C::BlockSize;

    fn inner_iv_init(cipher: C, iv: &GenericArray<u8, Self::IvSize>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
        }
    }
}

impl<C: BlockEncryptMut + BlockCipher> IvState for Encrypt<C> {
    fn iv_state(&self) -> GenericArray<u8, Self::IvSize> {
        self.iv.clone()
    }
}

/// CFB-8 mode decryptor.
#[derive(Clone)]
pub struct Decrypt<C: BlockEncryptMut + BlockCipher> {
    cipher: C,
    iv: Block<C>,
}

impl<C: BlockEncryptMut + BlockCipher> BlockDecryptMut for Decrypt<C> {
    fn decrypt_block(&mut self, mut block: impl InOutVal<Block<Self>>) {
        let mut t = self.iv.clone();
        self.cipher.encrypt_block(&mut t);
        let r = block.get_in()[0];
        block.get_out()[0] = r ^ t[0];
        let n = self.iv.len();
        for i in 0..n - 1 {
            self.iv[i] = self.iv[i + 1];
        }
        self.iv[n - 1] = r;
    }
}

impl<C: BlockEncryptMut + BlockCipher> BlockProcessing for Decrypt<C> {
    type BlockSize = U1;
}

impl<C: BlockEncryptMut + BlockCipher> AsyncStreamCipher for Decrypt<C> {}

impl<C: BlockEncryptMut + BlockCipher> InnerIvInit for Decrypt<C> {
    type Inner = C;
    type IvSize = C::BlockSize;

    fn inner_iv_init(cipher: C, iv: &GenericArray<u8, Self::IvSize>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
        }
    }
}

impl<C: BlockEncryptMut + BlockCipher> IvState for Decrypt<C> {
    fn iv_state(&self) -> GenericArray<u8, Self::IvSize> {
        self.iv.clone()
    }
}
