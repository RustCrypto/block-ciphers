use generic_array::GenericArray;
use generic_array::typenum::Unsigned;
use block_cipher_trait::BlockCipher;
use traits::{BlockMode, BlockModeIv};
use tools::xor;

pub struct Ofb<C: BlockCipher>{
    cipher: C,
    iv: GenericArray<u8, C::BlockSize>,
}

impl<C: BlockCipher> BlockModeIv<C> for Ofb<C> {
    fn new(cipher: C, iv: &GenericArray<u8, C::BlockSize>) -> Self {
        Self { cipher, iv: iv.clone() }
    }
}

impl<C: BlockCipher> BlockMode<C> for Ofb<C> {
    fn encrypt_nopad(&mut self, buffer: &mut [u8]) {
        let bs = C::BlockSize::to_usize();
        assert_eq!(buffer.len() % bs, 0);

        for block in buffer.chunks_mut(bs) {
            self.cipher.encrypt_block(&mut self.iv);
            xor(block, self.iv.as_slice());
        }
    }

    fn decrypt_nopad(&mut self, buffer: &mut [u8]) {
        self.encrypt_nopad(buffer);
    }
}
