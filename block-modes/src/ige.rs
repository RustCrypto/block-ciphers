use block_cipher_trait::generic_array::typenum::{
    B0, B1, Prod, U2, UInt, UTerm, Unsigned,
};
use block_cipher_trait::generic_array::{ArrayLength, GenericArray};
use block_cipher_trait::BlockCipher;
use block_padding::Padding;
use byte_tools::copy;
use core::marker::PhantomData;
use core::ops::Mul;
use traits::{BlockMode, BlockModeError, BlockModeIv};
use utils::{xor};

type IgeIvBlockSize<C> = Prod<<C as BlockCipher>::BlockSize, U2>;

// Infinite Garble Extension (IGE)

// Implementation derived from:
// https://mgp25.com/AESIGE/

pub struct Ige<C: BlockCipher, P: Padding>
where
    C::BlockSize: Mul<UInt<UInt<UTerm, B1>, B0>>,
    <C::BlockSize as Mul<UInt<UInt<UTerm, B1>, B0>>>::Output: ArrayLength<u8>,
{
    cipher: C,
    iv: GenericArray<u8, IgeIvBlockSize<C>>,
    _p: PhantomData<P>,
}

impl<C: BlockCipher, P: Padding> BlockModeIv<C, P> for Ige<C, P>
where
    C::BlockSize: Mul<UInt<UInt<UTerm, B1>, B0>>,
    <C::BlockSize as Mul<UInt<UInt<UTerm, B1>, B0>>>::Output: ArrayLength<u8>,
{
    type IvBlockSize = IgeIvBlockSize<C>;

    fn new(cipher: C, iv: &GenericArray<u8, Self::IvBlockSize>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
            _p: Default::default(),
        }
    }
}

impl<C: BlockCipher, P: Padding> BlockMode<C, P> for Ige<C, P>
where
    C::BlockSize: Mul<UInt<UInt<UTerm, B1>, B0>>,
    <C::BlockSize as Mul<UInt<UInt<UTerm, B1>, B0>>>::Output: ArrayLength<u8>,
{
    fn encrypt_nopad(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<(), BlockModeError> {
        let bs = C::BlockSize::to_usize();
        if buffer.len() % bs != 0 {
            Err(BlockModeError)?
        }

        let (mut y_prev, x_prev) = self.iv.split_at_mut(bs);
        let mut x_temp =
            GenericArray::<u8, C::BlockSize>::clone_from_slice(&buffer[..bs]);

        for mut y in buffer.chunks_mut(bs) {
            copy(y, &mut x_temp);

            xor(y, y_prev);

            self.cipher
                .encrypt_block(GenericArray::from_mut_slice(&mut y));

            xor(y, x_prev);

            copy(&x_temp, x_prev);
            y_prev = y;
        }

        Ok(())
    }

    fn decrypt_nopad(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<(), BlockModeError> {
        let bs = C::BlockSize::to_usize();
        if buffer.len() % bs != 0 {
            Err(BlockModeError)?
        }

        let (x_prev, mut y_prev) = self.iv.split_at_mut(bs);
        let mut x_temp =
            GenericArray::<u8, C::BlockSize>::clone_from_slice(&buffer[..bs]);

        for mut y in buffer.chunks_mut(bs) {
            copy(y, &mut x_temp);

            xor(y, y_prev);

            self.cipher
                .decrypt_block(GenericArray::from_mut_slice(&mut y));

            xor(y, x_prev);

            copy(&x_temp, x_prev);
            y_prev = y;
        }

        Ok(())
    }
}
