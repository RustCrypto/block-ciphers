use super::BlockCipher;
use traits::{BlockMode, Padding};

pub struct Ecb<C: BlockCipher> {
    cipher: C
}

impl<C: BlockCipher> Ecb<C> {
    pub fn new(cipher: C) -> Self {
        Self { cipher }
    }
}

impl<C, P> BlockMode<C, P> for Ecb<C> where C: BlockCipher, P: Padding {
    fn encrypt_nopad(&mut self, buffer: &mut [u8]) {
        self.cipher.encrypt_blocks(buffer);
    }

    fn decrypt_nopad(&mut self, buffer: &mut [u8]) {
        self.cipher.decrypt_blocks(buffer);
    }
}
