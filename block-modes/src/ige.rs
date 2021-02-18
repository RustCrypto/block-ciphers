use crate::{
    traits::{BlockMode, IvState},
    utils::{xor, Block},
};
use block_padding::Padding;
use cipher::{
    generic_array::{
        typenum::{Prod, Unsigned, U2},
        ArrayLength, GenericArray,
    },
    BlockCipher, BlockDecrypt, BlockEncrypt, NewBlockCipher,
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
    C::BlockSize: Mul<U2>,
    IgeIvBlockSize<C>: ArrayLength<u8>,
{
    cipher: C,
    x: GenericArray<u8, C::BlockSize>,
    y: GenericArray<u8, C::BlockSize>,
    _p: PhantomData<P>,
}

impl<C, P> BlockMode<C, P> for Ige<C, P>
where
    C: BlockCipher + NewBlockCipher + BlockEncrypt + BlockDecrypt,
    P: Padding,
    C::BlockSize: Mul<U2>,
    IgeIvBlockSize<C>: ArrayLength<u8>,
{
    type IvSize = IgeIvBlockSize<C>;

    fn new(cipher: C, iv: &GenericArray<u8, Self::IvSize>) -> Self {
        let (y, x) = iv.split_at(C::BlockSize::to_usize());
        Ige {
            cipher,
            x: GenericArray::clone_from_slice(x),
            y: GenericArray::clone_from_slice(y),
            _p: Default::default(),
        }
    }

    fn encrypt_blocks(&mut self, blocks: &mut [Block<C>]) {
        for block in blocks {
            let t = block.clone();
            xor(block, &self.y);
            self.cipher.encrypt_block(block);
            xor(block, &self.x);
            self.x = t;
            self.y = block.clone();
        }
    }

    fn decrypt_blocks(&mut self, blocks: &mut [Block<C>]) {
        for block in blocks {
            let t = block.clone();
            xor(block, &self.x);
            self.cipher.decrypt_block(block);
            xor(block, &self.y);
            self.y = t;
            self.x = block.clone();
        }
    }
}

impl<C, P> IvState<C, P> for Ige<C, P>
where
    C: BlockCipher + NewBlockCipher + BlockEncrypt + BlockDecrypt,
    P: Padding,
    C::BlockSize: Mul<U2>,
    IgeIvBlockSize<C>: ArrayLength<u8>,
{
    fn iv_state(&self) -> GenericArray<u8, Self::IvSize> {
        let iv = &[self.y.as_slice(), self.x.as_slice()].concat();
        GenericArray::<u8, Self::IvSize>::clone_from_slice(iv)
    }
}
