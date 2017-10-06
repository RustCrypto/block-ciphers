use generic_array::GenericArray;
use generic_array::typenum::{Unsigned, U8};
use super::BlockCipher;
use traits::{BlockMode, Padding};
use tools::xor;
use core::mem;

pub struct Ctr64<C: BlockCipher> {
    cipher: C,
    nonce: u64,
}

impl<C: BlockCipher<BlockSize=U8>> Ctr64<C> {
    pub fn new(cipher: C, iv: GenericArray<u8, C::BlockSize>) -> Self {
        let nonce: u64 = unsafe { mem::transmute(iv) };
        Self { cipher, nonce: nonce.to_le() }
    }
}

impl<C, P> BlockMode<C, P> for Ctr64<C>
    where C: BlockCipher<BlockSize=U8>, P: Padding
{
    fn encrypt_nopad(&mut self, buffer: &mut [u8]) {
        let bs = C::BlockSize::to_usize();
        assert_eq!(buffer.len() % bs, 0);

        for block in buffer.chunks_mut(bs) {
            let mut buf: GenericArray<u8, U8> = unsafe {
                mem::transmute(self.nonce.to_le())
            };
            self.cipher.encrypt_block(&mut buf);
            xor(block, &buf);
            self.nonce = self.nonce.wrapping_add(1);
        }
    }

    fn decrypt_nopad(&mut self, buffer: &mut [u8]) {
        BlockMode::<C, P>::encrypt_nopad(self, buffer);
    }
}
