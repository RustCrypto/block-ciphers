use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::generic_array::typenum::Unsigned;
use block_cipher_trait::BlockCipher;
use block_padding::Padding;
use traits::{BlockMode, BlockModeError, BlockModeIv};
use core::marker::PhantomData;
use utils::xor;

pub struct Ofb<C: BlockCipher, P: Padding> {
    cipher: C,
    iv: GenericArray<u8, C::BlockSize>,
    _p: PhantomData<P>,
}

impl<C: BlockCipher, P: Padding> BlockModeIv<C, P> for Ofb<C, P> {
    type IvBlockSize = C::BlockSize;

    fn new(cipher: C, iv: &GenericArray<u8, C::BlockSize>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
            _p: Default::default(),
        }
    }
}

impl<C: BlockCipher, P: Padding> BlockMode<C, P> for Ofb<C, P> {
    fn encrypt_nopad(
        &mut self, buffer: &mut [u8]
    ) -> Result<(), BlockModeError> {
        let bs = C::BlockSize::to_usize();
        if buffer.len() % bs != 0 {
            Err(BlockModeError)?
        }

        for block in buffer.chunks_mut(bs) {
            self.cipher.encrypt_block(&mut self.iv);
            xor(block, self.iv.as_slice());
        }
        Ok(())
    }

    fn decrypt_nopad(
        &mut self, buffer: &mut [u8]
    ) -> Result<(), BlockModeError> {
        self.encrypt_nopad(buffer)
    }
}
