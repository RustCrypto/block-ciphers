use block_cipher_trait::generic_array::{GenericArray, ArrayLength};
use block_cipher_trait::generic_array::typenum::{Unsigned, U8};
use block_cipher_trait::BlockCipher;
use block_padding::Padding;
use traits::{BlockMode, BlockModeIv, BlockModeError};
use utils::xor;
use core::mem;
use core::marker::PhantomData;

pub struct Ctr64<C, P>
    where C: BlockCipher<BlockSize=U8>, P: Padding,
        C::ParBlocks: ArrayLength<GenericArray<u8, U8>>
{
    cipher: C,
    counter: u64,
    _p: PhantomData<P>,
}

impl<C, P> BlockModeIv<C, P> for Ctr64<C, P>
    where C: BlockCipher<BlockSize=U8>, P: Padding,
        C::ParBlocks: ArrayLength<GenericArray<u8, U8>>
{
    fn new(cipher: C, nonce: &GenericArray<u8, C::BlockSize>) -> Self {
        // native endian counter
        let counter = unsafe { mem::transmute_copy::<_, u64>(nonce).to_be() };
        Self { cipher,  counter, _p: Default::default() }
    }
}

impl<C, P> BlockMode<C, P> for Ctr64<C, P>
    where C: BlockCipher<BlockSize=U8>, P: Padding,
        C::ParBlocks: ArrayLength<GenericArray<u8, U8>>
{
    fn encrypt_nopad(&mut self, buffer: &mut [u8])
        -> Result<(), BlockModeError>
    {
        let bs = C::BlockSize::to_usize();
        assert_eq!(buffer.len() % bs, 0);

        for block in buffer.chunks_mut(bs) {
            let res = self.counter.to_be();
            self.counter = self.counter.wrapping_add(1);
            let mut buf = unsafe { mem::transmute(res) };
            self.cipher.encrypt_block(&mut buf);
            xor(block, &buf);
        }
        Ok(())
    }

    fn decrypt_nopad(&mut self, buffer: &mut [u8])
        -> Result<(), BlockModeError>
    {
        self.encrypt_nopad(buffer)
    }
}
