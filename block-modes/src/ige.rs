use crate::{
    traits::BlockMode,
    utils::{xor, Block},
};
use block_padding::Padding;
use byte_tools::copy;
use cipher::{
    block::{BlockCipher, BlockDecrypt, BlockEncrypt, NewBlockCipher},
    generic_array::{
        typenum::{Prod, UInt, UTerm, Unsigned, B0, B1, U2},
        ArrayLength, GenericArray,
    },
};
use core::{marker::PhantomData, ops::Mul};

type IgeIvBlockSize<C> = Prod<<C as BlockCipher>::BlockSize, U2>;

/// [Infinite Garble Extension][1] (IGE) block cipher mode instance.
///
/// [1]: https://www.links.org/files/openssl-ige.pdf
pub struct Ige<C, P>
where
    C: BlockCipher + NewBlockCipher + BlockEncrypt + BlockDecrypt,
    P: Padding,
    C::BlockSize: Mul<UInt<UInt<UTerm, B1>, B0>>,
    <C::BlockSize as Mul<UInt<UInt<UTerm, B1>, B0>>>::Output: ArrayLength<u8>,
{
    cipher: C,
    iv: GenericArray<u8, IgeIvBlockSize<C>>,
    _p: PhantomData<P>,
}

// Implementation derived from:
// https://mgp25.com/AESIGE/

impl<C, P> BlockMode<C, P> for Ige<C, P>
where
    C: BlockCipher + NewBlockCipher + BlockEncrypt + BlockDecrypt,
    P: Padding,
    C::BlockSize: Mul<UInt<UInt<UTerm, B1>, B0>>,
    <C::BlockSize as Mul<UInt<UInt<UTerm, B1>, B0>>>::Output: ArrayLength<u8>,
{
    type IvSize = IgeIvBlockSize<C>;

    fn new(cipher: C, iv: &GenericArray<u8, Self::IvSize>) -> Self {
        Ige {
            cipher,
            iv: iv.clone(),
            _p: Default::default(),
        }
    }

    fn encrypt_blocks(&mut self, blocks: &mut [Block<C>]) {
        let block_size = C::BlockSize::to_usize();

        let (mut y_prev, x_prev) = self.iv.split_at_mut(block_size);
        let mut x_temp = GenericArray::<u8, C::BlockSize>::default();

        for block in blocks {
            copy(block, &mut x_temp);

            xor(block, y_prev);

            self.cipher.encrypt_block(block);

            xor(block, x_prev);

            copy(&x_temp, x_prev);
            y_prev = block;
        }
    }

    fn decrypt_blocks(&mut self, blocks: &mut [Block<C>]) {
        let block_size = C::BlockSize::to_usize();

        let (x_prev, mut y_prev) = self.iv.split_at_mut(block_size);
        let mut x_temp = GenericArray::<u8, C::BlockSize>::default();

        for block in blocks {
            copy(block, &mut x_temp);

            xor(block, y_prev);

            self.cipher.decrypt_block(block);

            xor(block, x_prev);

            copy(&x_temp, x_prev);
            y_prev = block;
        }
    }
}
