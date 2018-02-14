use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::generic_array::typenum::{Unsigned, U8, U16};
use block_cipher_trait::BlockCipher;
use traits::{BlockMode, BlockModeIv};
use tools::xor;
use core::mem;

pub struct Ctr128<C> where C: BlockCipher<BlockSize=U16> {
    cipher: C,
    counter: [u64; 2],
}

#[inline(always)]
fn conv_be(val: &mut [u64; 2]) {
    val[0] = val[0].to_be();
    val[1] = val[1].to_be();
}

impl<C> BlockModeIv<C> for Ctr128<C> where C: BlockCipher<BlockSize=U16> {
    fn new(cipher: C, nonce: &GenericArray<u8, C::BlockSize>) -> Self {
        let mut counter: [u64; 2] = unsafe { mem::transmute_copy(nonce) };
        conv_be(&mut counter);

        Self { cipher,  counter }
    }
}

impl<C> Ctr128<C> where C: BlockCipher<BlockSize=U16> {
    #[inline(always)]
    // we increment only second half
    fn inc_counter(&mut self) {
        self.counter[1] = self.counter[1].wrapping_add(1);
    }

    #[inline(always)]
    fn next_buf(&mut self) -> GenericArray<u8, C::BlockSize> {
        let mut res = self.counter.clone();
        conv_be(&mut res);

        self.inc_counter();

        unsafe { mem::transmute(res) }
    }
}

impl<C> BlockMode<C> for Ctr128<C> where C: BlockCipher<BlockSize=U16> {
    fn encrypt_nopad(&mut self, buffer: &mut [u8]) {
        let bs = C::BlockSize::to_usize();
        assert_eq!(buffer.len() % bs, 0);

        for block in buffer.chunks_mut(bs) {
            let mut buf = self.next_buf();
            self.cipher.encrypt_block(&mut buf);
            xor(block, &buf);
        }
    }

    fn decrypt_nopad(&mut self, buffer: &mut [u8]) {
        self.encrypt_nopad(buffer);
    }
}


pub struct Ctr64<C> where C: BlockCipher<BlockSize=U8> {
    cipher: C,
    counter: u64,
}

impl<C> BlockModeIv<C> for Ctr64<C> where C: BlockCipher<BlockSize=U8> {
    fn new(cipher: C, nonce: &GenericArray<u8, C::BlockSize>) -> Self {
        // native endian counter
        let counter = unsafe { mem::transmute_copy::<_, u64>(nonce).to_be() };
        Self { cipher,  counter }
    }
}

impl<C> BlockMode<C> for Ctr64<C> where C: BlockCipher<BlockSize=U8> {
    fn encrypt_nopad(&mut self, buffer: &mut [u8]) {
        let bs = C::BlockSize::to_usize();
        assert_eq!(buffer.len() % bs, 0);

        for block in buffer.chunks_mut(bs) {
            let res = self.counter.to_be();
            self.counter = self.counter.wrapping_add(1);
            let mut buf = unsafe { mem::transmute(res) };
            self.cipher.encrypt_block(&mut buf);
            xor(block, &buf);
        }
    }

    fn decrypt_nopad(&mut self, buffer: &mut [u8]) {
        self.encrypt_nopad(buffer);
    }
}
