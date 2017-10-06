use block_cipher_trait::BlockCipher;
use traits::BlockMode;

pub struct Ecb<C: BlockCipher> {
    cipher: C
}

impl<C: BlockCipher> Ecb<C> {
    pub fn new(cipher: C) -> Self {
        Self { cipher }
    }
}

impl<C: BlockCipher> BlockMode<C> for Ecb<C> {
    fn encrypt_nopad(&mut self, buffer: &mut [u8]) {
        self.cipher.encrypt_blocks(buffer).unwrap();
    }

    fn decrypt_nopad(&mut self, buffer: &mut [u8]) {
        self.cipher.decrypt_blocks(buffer).unwrap();
    }
}
