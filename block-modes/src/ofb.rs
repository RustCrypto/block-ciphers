/// [Output feedback][1] (OFB) mode.
///
/// [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_feedback_(OFB)
use cipher::{
    generic_array::GenericArray, Block, BlockCipher, StreamCipherCore, BlockEncryptMut,
    BlockProcessing, InnerIvInit, IvState, InOutVal, BlockDecryptMut, errors::LoopError,
};
use crate::xor_ret;

/// [Output feedback][1] (OFB) mode.
///
/// [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_feedback_(OFB)
#[derive(Clone)]
pub struct Ofb<C: BlockEncryptMut + BlockCipher> {
    cipher: C,
    iv: Block<C>,
}

impl<C: BlockEncryptMut + BlockCipher> StreamCipherCore for Ofb<C> {
    fn gen_keystream_block(&mut self) -> Result<Block<Self>, LoopError> {
        self.cipher.encrypt_block(&mut self.iv);
        Ok(self.iv.clone())
    }
}

impl<C: BlockEncryptMut + BlockCipher> BlockProcessing for Ofb<C> {
    type BlockSize = C::BlockSize;
}

impl<C: BlockEncryptMut + BlockCipher> InnerIvInit for Ofb<C> {
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

impl<C: BlockEncryptMut + BlockCipher> IvState for Ofb<C> {
    #[inline]
    fn iv_state(&self) -> GenericArray<u8, Self::IvSize> {
        self.iv.clone()
    }
}

impl<C: BlockEncryptMut + BlockCipher> BlockEncryptMut for Ofb<C> {
    fn encrypt_block(&mut self, mut block: impl InOutVal<Block<Self>>) {
        self.cipher.encrypt_block(&mut self.iv);
        *block.get_out() = xor_ret(&self.iv, block.get_in());
    }
}

impl<C: BlockEncryptMut + BlockCipher> BlockDecryptMut for Ofb<C> {
    fn decrypt_block(&mut self, mut block: impl InOutVal<Block<Self>>) {
        self.cipher.encrypt_block(&mut self.iv);
        *block.get_out() = xor_ret(&self.iv, block.get_in());
    }
}
