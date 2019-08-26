use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::BlockCipher;
use block_padding::Padding;
use core::marker::PhantomData;
use traits::BlockMode;
use utils::{xor, Block};

/// [Propagating Cipher Block Chaining][1] (PCBC) mode instance.
///
/// [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#PCBC
pub struct Pcbc<C: BlockCipher, P: Padding> {
    cipher: C,
    iv: GenericArray<u8, C::BlockSize>,
    _p: PhantomData<P>,
}

impl<C: BlockCipher, P: Padding> Pcbc<C, P> {
    pub fn new(cipher: C, iv: &Block<C>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
            _p: Default::default(),
        }
    }
}

impl<C: BlockCipher, P: Padding> BlockMode<C, P> for Pcbc<C, P> {
    fn new(cipher: C, iv: &GenericArray<u8, C::BlockSize>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
            _p: Default::default(),
        }
    }

    fn encrypt_blocks(&mut self, blocks: &mut [Block<C>]) {
        for block in blocks {
            let plaintext = block.clone();
            xor(block, &self.iv);
            self.cipher.encrypt_block(block);
            self.iv = plaintext;
            xor(&mut self.iv, block);
        }
    }

    fn decrypt_blocks(&mut self, blocks: &mut [Block<C>]) {
        for block in blocks {
            let ciphertext = block.clone();
            self.cipher.decrypt_block(block);
            xor(block, &self.iv);
            self.iv = ciphertext;
            xor(&mut self.iv, block);
        }
    }
}
