/// [Output feedback][1] (OFB) mode.
///
/// [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_feedback_(OFB)
use cipher::{
    errors::LoopError,
    generic_array::{ArrayLength, GenericArray},
    Block, BlockCipher, BlockDecryptMut, BlockEncryptMut, BlockProcessing, InOutVal, InnerIvInit,
    IvState, StreamCipherCore,
};

/// Output feedback (OFB) mode.
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

#[inline(always)]
fn xor_ret<N: ArrayLength<u8>>(
    buf1: &GenericArray<u8, N>,
    buf2: &GenericArray<u8, N>,
) -> GenericArray<u8, N> {
    let mut res = GenericArray::<u8, N>::default();
    for i in 0..N::USIZE {
        res[i] = buf1[i] ^ buf2[i];
    }
    res
}
