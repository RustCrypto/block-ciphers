use block_cipher_trait::generic_array::{ArrayLength, GenericArray};
use block_cipher_trait::generic_array::typenum::{U16, Unsigned};
use block_cipher_trait::BlockCipher;
use block_padding::Padding;
use traits::{BlockMode, BlockModeError, BlockModeIv};
use utils::xor;
use core::mem;
use core::marker::PhantomData;

pub struct Ctr128<C, P>
where
    C: BlockCipher<BlockSize = U16>,
    P: Padding,
    C::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
{
    cipher: C,
    counter: [u64; 2],
    _p: PhantomData<P>,
}

#[inline(always)]
fn conv_be(val: &mut [u64; 2]) {
    val[0] = val[0].to_be();
    val[1] = val[1].to_be();
}

impl<C, P> BlockModeIv<C, P> for Ctr128<C, P>
where
    C: BlockCipher<BlockSize = U16>,
    P: Padding,
    C::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
{
    type IvBlockSize = C::BlockSize;

    fn new(cipher: C, nonce: &GenericArray<u8, C::BlockSize>) -> Self {
        let mut counter: [u64; 2] = unsafe { mem::transmute_copy(nonce) };
        conv_be(&mut counter);

        Self {
            cipher,
            counter,
            _p: Default::default(),
        }
    }
}

impl<C, P> Ctr128<C, P>
where
    C: BlockCipher<BlockSize = U16>,
    P: Padding,
    C::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
{
    #[inline(always)]
    // we increment only second half
    fn inc_counter(&mut self) {
        //self.counter[1] = self.counter[1].wrapping_add(1);
        let (v, f) = self.counter[1].overflowing_add(1);
        self.counter[1] = v;
        if f {
            self.counter[0] = self.counter[0].wrapping_add(1);
        }
    }

    #[inline(always)]
    fn next_buf(&mut self) -> GenericArray<u8, U16> {
        let mut res = self.counter.clone();
        conv_be(&mut res);

        self.inc_counter();

        unsafe { mem::transmute(res) }
    }
}

impl<C, P> BlockMode<C, P> for Ctr128<C, P>
where
    C: BlockCipher<BlockSize = U16>,
    P: Padding,
    C::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
{
    fn encrypt_nopad(
        &mut self, buffer: &mut [u8]
    ) -> Result<(), BlockModeError> {
        let bs = C::BlockSize::to_usize();
        assert_eq!(buffer.len() % bs, 0);

        for block in buffer.chunks_mut(bs) {
            let mut buf = self.next_buf();
            self.cipher.encrypt_block(&mut buf);
            xor(block, &buf);
        }
        Ok(())
    }

    fn decrypt_nopad(
        &mut self, buffer: &mut [u8]
    ) -> Result<(), BlockModeError> {
        self.encrypt_nopad(buffer)
    }
}
