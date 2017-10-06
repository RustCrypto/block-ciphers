use generic_array::GenericArray;
use generic_array::typenum::Unsigned;
use block_cipher_trait::BlockCipher;
use traits::BlockMode;
use tools::xor;

pub struct Pcbc<C: BlockCipher>{
    cipher: C,
    iv: GenericArray<u8, C::BlockSize>,
}

impl<C: BlockCipher> Pcbc<C> {
    pub fn new(cipher: C, iv: GenericArray<u8, C::BlockSize>) -> Self {
        Self { cipher, iv }
    }
}

impl<C: BlockCipher> BlockMode<C> for Pcbc<C> {
    fn encrypt_nopad(&mut self, buffer: &mut [u8]) {
        let bs = C::BlockSize::to_usize();
        assert_eq!(buffer.len() % bs, 0);

        for block in buffer.chunks_mut(bs) {
            let plaintext = GenericArray::clone_from_slice(block);
            xor(block, self.iv.as_slice());
            self.cipher.encrypt_block(GenericArray::from_mut_slice(block));
            self.iv = plaintext;
            xor(self.iv.as_mut_slice(), block);
        }
    }

    fn decrypt_nopad(&mut self, buffer: &mut [u8]) {
        let bs = C::BlockSize::to_usize();
        assert_eq!(buffer.len() % bs, 0);

        for block in buffer.chunks_mut(bs) {
            let ciphertext = GenericArray::clone_from_slice(block);
            self.cipher.decrypt_block(GenericArray::from_mut_slice(block));
            xor(block, self.iv.as_slice());
            self.iv = ciphertext;
            xor(self.iv.as_mut_slice(), block);
        }
    }
}
