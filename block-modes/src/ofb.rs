use generic_array::GenericArray;
use generic_array::typenum::Unsigned;
use super::BlockCipher;
use traits::{BlockMode, Padding};
use tools::xor;

pub struct Ofb<C: BlockCipher>{
    cipher: C,
    iv: GenericArray<u8, C::BlockSize>,
}

impl<C: BlockCipher> Ofb<C> {
    pub fn new(cipher: C, iv: GenericArray<u8, C::BlockSize>) -> Self {
        Self { cipher, iv }
    }
}

impl<C, P> BlockMode<C, P> for Ofb<C> where C: BlockCipher, P: Padding {
    fn encrypt_nopad(&mut self, buffer: &mut [u8]) {
        let bs = C::BlockSize::to_usize();
        assert_eq!(buffer.len() % bs, 0);

        for block in buffer.chunks_mut(bs) {
            self.cipher.encrypt_block(&mut self.iv);
            xor(block, self.iv.as_slice());
        }
    }

    fn decrypt_nopad(&mut self, buffer: &mut [u8]) {
        BlockMode::<C, P>::encrypt_nopad(self, buffer);
    }
}
