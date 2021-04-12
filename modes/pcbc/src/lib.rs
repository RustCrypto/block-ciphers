//! [Propagating Cipher Block Chaining][1] (PCBC) mode.
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Propagating_cipher_block_chaining_(PCBC)
use cipher::{
    generic_array::{ArrayLength, GenericArray},
    Block, BlockCipher, BlockDecryptMut, BlockEncryptMut, BlockProcessing, InOutVal, InnerIvInit,
    IvState,
};

/// PCBC mode encryptor.
#[derive(Clone)]
pub struct Encrypt<C: BlockEncryptMut + BlockCipher> {
    cipher: C,
    iv: Block<C>,
}

impl<C: BlockEncryptMut + BlockCipher> BlockEncryptMut for Encrypt<C> {
    fn encrypt_block(&mut self, mut block: impl InOutVal<Block<Self>>) {
        let mut t = self.iv.clone();
        xor(&mut t, block.get_in());
        self.cipher.encrypt_block((&t, block.get_out()));
        xor(&mut t, block.get_out());
        self.iv = t;
    }
}

impl<C: BlockEncryptMut + BlockCipher> BlockProcessing for Encrypt<C> {
    type BlockSize = C::BlockSize;
}

impl<C: BlockEncryptMut + BlockCipher> InnerIvInit for Encrypt<C> {
    type Inner = C;
    type IvSize = C::BlockSize;

    #[inline]
    fn inner_iv_init(cipher: C, iv: &GenericArray<u8, Self::IvSize>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
        }
    }
}

impl<C: BlockEncryptMut + BlockCipher> IvState for Encrypt<C> {
    #[inline]
    fn iv_state(&self) -> GenericArray<u8, Self::IvSize> {
        self.iv.clone()
    }
}

/// PCBC mode decryptor.
#[derive(Clone)]
pub struct Decrypt<C: BlockDecryptMut + BlockCipher> {
    cipher: C,
    iv: Block<C>,
}

impl<C: BlockDecryptMut + BlockCipher> BlockDecryptMut for Decrypt<C> {
    fn decrypt_block(&mut self, mut block: impl InOutVal<Block<Self>>) {
        let mut t = Default::default();
        self.cipher.decrypt_block((block.get_in(), &mut t));
        xor(&mut t, &self.iv);
        self.iv.copy_from_slice(block.get_in());
        block.get_out().copy_from_slice(&t);
        xor(&mut self.iv, &t);
    }
}

impl<C: BlockDecryptMut + BlockCipher> BlockProcessing for Decrypt<C> {
    type BlockSize = C::BlockSize;
}

impl<C: BlockDecryptMut + BlockCipher> InnerIvInit for Decrypt<C> {
    type Inner = C;
    type IvSize = C::BlockSize;

    #[inline]
    fn inner_iv_init(cipher: C, iv: &GenericArray<u8, Self::IvSize>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
        }
    }
}

impl<C: BlockDecryptMut + BlockCipher> IvState for Decrypt<C> {
    fn iv_state(&self) -> GenericArray<u8, Self::IvSize> {
        self.iv.clone()
    }
}

#[inline(always)]
fn xor<N: ArrayLength<u8>>(out: &mut GenericArray<u8, N>, buf: &GenericArray<u8, N>) {
    for (a, b) in out.iter_mut().zip(buf) {
        *a ^= *b;
    }
}
