use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::generic_array::typenum::Unsigned;
use block_cipher_trait::BlockCipher;
use block_padding::Padding;
use traits::{BlockMode, BlockModeError, BlockModeIv};
use utils::xor;
use core::marker::PhantomData;

pub struct Pcbc<C: BlockCipher, P: Padding> {
    cipher: C,
    iv: GenericArray<u8, C::BlockSize>,
    _p: PhantomData<P>,
}

impl<C: BlockCipher, P: Padding> BlockModeIv<C, P> for Pcbc<C, P> {
    fn new(cipher: C, iv: &GenericArray<u8, C::BlockSize>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
            _p: Default::default(),
        }
    }
}

impl<C: BlockCipher, P: Padding> BlockMode<C, P> for Pcbc<C, P> {
    fn encrypt_nopad(
        &mut self, buffer: &mut [u8]
    ) -> Result<(), BlockModeError> {
        let bs = C::BlockSize::to_usize();
        if buffer.len() % bs != 0 {
            Err(BlockModeError)?
        }

        for block in buffer.chunks_mut(bs) {
            let plaintext = GenericArray::clone_from_slice(block);
            xor(block, self.iv.as_slice());
            self.cipher
                .encrypt_block(GenericArray::from_mut_slice(block));
            self.iv = plaintext;
            xor(self.iv.as_mut_slice(), block);
        }
        Ok(())
    }

    fn decrypt_nopad(
        &mut self, buffer: &mut [u8]
    ) -> Result<(), BlockModeError> {
        let bs = C::BlockSize::to_usize();
        if buffer.len() % bs != 0 {
            Err(BlockModeError)?
        }

        for block in buffer.chunks_mut(bs) {
            let ciphertext = GenericArray::clone_from_slice(block);
            self.cipher
                .decrypt_block(GenericArray::from_mut_slice(block));
            xor(block, self.iv.as_slice());
            self.iv = ciphertext;
            xor(self.iv.as_mut_slice(), block);
        }
        Ok(())
    }
}
