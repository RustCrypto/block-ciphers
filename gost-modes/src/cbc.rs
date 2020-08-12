use crate::{utils::xor, GostPadding};
use block_modes::block_cipher::{Block, BlockCipher, NewBlockCipher};
use block_modes::block_padding::Padding;
use block_modes::BlockMode;
use core::marker::PhantomData;
use core::ops::Mul;
use generic_array::typenum::type_operators::{IsGreater, IsLessOrEqual};
use generic_array::typenum::{Prod, Unsigned, U0, U1, U255};
use generic_array::{ArrayLength, GenericArray};

/// Cipher Block Chaining (CBC) mode of operation as defined in GOST R 34.13-2015
///
/// Type parameters:
/// - `C`: block cipher.
/// - `P`: padding algorithm. Default: `GostPadding`.
/// - `Z`: nonce length in block sizes. Default: 1.
///
/// With default parameters this mode is fully equivalent to the `Cbc` mode defined
/// in the `block-modes` crate.
#[derive(Clone)]
pub struct GostCbc<C, P = GostPadding, Z = U1>
where
    C: BlockCipher + NewBlockCipher,
    C::BlockSize: IsLessOrEqual<U255>,
    Z: ArrayLength<Block<C>> + Unsigned + Mul<C::BlockSize> + IsGreater<U0> + IsLessOrEqual<U255>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
    P: Padding,
{
    cipher: C,
    state: GenericArray<Block<C>, Z>,
    pos: u8,
    _p: PhantomData<P>,
}

impl<C, P, Z> BlockMode<C, P> for GostCbc<C, P, Z>
where
    C: BlockCipher + NewBlockCipher,
    C::BlockSize: IsLessOrEqual<U255>,
    Z: ArrayLength<Block<C>> + Unsigned + Mul<C::BlockSize> + IsGreater<U0> + IsLessOrEqual<U255>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
    P: Padding,
{
    type IvSize = Prod<Z, C::BlockSize>;

    fn new(cipher: C, iv: &GenericArray<u8, Self::IvSize>) -> Self {
        let bs = C::BlockSize::USIZE;
        let mut state = GenericArray::<Block<C>, Z>::default();
        for (block, chunk) in state.iter_mut().zip(iv.chunks(bs)) {
            *block = GenericArray::clone_from_slice(chunk);
        }
        Self {
            cipher,
            state,
            pos: 0,
            _p: Default::default(),
        }
    }

    fn encrypt_blocks(&mut self, blocks: &mut [Block<C>]) {
        for block in blocks {
            let sb = &mut self.state[self.pos as usize];
            xor(block, sb);
            self.cipher.encrypt_block(block);
            *sb = block.clone();
            self.pos += 1;
            self.pos %= Z::U8;
        }
    }

    fn decrypt_blocks(&mut self, blocks: &mut [Block<C>]) {
        for block in blocks {
            let pos = self.pos as usize;
            let b = self.state[pos].clone();
            self.state[pos] = block.clone();
            self.cipher.decrypt_block(block);
            xor(block, &b);
            self.pos += 1;
            self.pos %= Z::U8;
        }
    }
}
