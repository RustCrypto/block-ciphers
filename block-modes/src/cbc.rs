use generic_array::GenericArray;
use generic_array::typenum::Unsigned;
use super::BlockCipher;
use traits::{BlockMode, Padding};
use tools::xor;

// difficulty with par_decrypt
pub struct Cbc<C: BlockCipher>{
    cipher: C,
    iv: GenericArray<u8, C::BlockSize>,
}

impl<C: BlockCipher> Cbc<C> {
    pub fn new(cipher: C, iv: GenericArray<u8, C::BlockSize>) -> Self {
        Self { cipher, iv }
    }
}

impl<C, P> BlockMode<C, P> for Cbc<C> where C: BlockCipher, P: Padding {
    fn encrypt_nopad(&mut self, buffer: &mut [u8]) {
        let bs = C::BlockSize::to_usize();
        assert_eq!(buffer.len() % bs, 0);
        self.iv = {
            let mut iv = self.iv.as_slice();
            for block in buffer.chunks_mut(bs) {
                xor(block, iv);
                self.cipher.encrypt_block(GenericArray::from_mut_slice(block));
                iv = block;
            }
            GenericArray::clone_from_slice(iv)
        };
    }

    fn decrypt_nopad(&mut self, buffer: &mut [u8]) {
        let bs = C::BlockSize::to_usize();
        assert_eq!(buffer.len() % bs, 0);

        for block in buffer.chunks_mut(bs) {
            let block_copy = GenericArray::clone_from_slice(block);
            self.cipher.decrypt_block(GenericArray::from_mut_slice(block));
            xor(block, self.iv.as_slice());
            self.iv = block_copy;
        }
    }
}
