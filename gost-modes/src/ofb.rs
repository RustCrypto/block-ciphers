use block_modes::BlockMode;
use crate::utils::{xor, Block};
use generic_array::{ArrayLength, GenericArray};
use generic_array::typenum::{U0, U1, Greater, Unsigned, Prod,};
use generic_array::typenum::type_operators::{IsLessOrEqual, IsGreater};
use block_modes::block_cipher::{BlockCipher, NewBlockCipher};
use stream_cipher::{NewStreamCipher, SyncStreamCipher, LoopError};
use core::marker::PhantomData;
use core::ops::Mul;

/// Output feedback (OFB) block mode instance as defined in GOST R 34.13-2015.
pub struct GostOfb<C, Z = U1, S = <C as BlockCipher>::BlockSize>
where
    C: BlockCipher + NewBlockCipher,
    S: Unsigned + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Z: Mul<C::BlockSize> + IsGreater<U0>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
{
    cipher: C,
    nonce: GenericArray<u8, <Z as Mul<C::BlockSize>>::Output>,
    pos: usize,
    _p: PhantomData<(S, Z)>,
}

// TODO: replace with FromBlockCipher trait impl
impl <C, Z, S> GostOfb<C, Z, S>
where
    C: BlockCipher + NewBlockCipher,
    S: Unsigned + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Z: Mul<C::BlockSize> + IsGreater<U0>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
{
    pub fn from_block_cipher(
        cipher: C,
        nonce: &GenericArray<u8, <Self as NewStreamCipher>::NonceSize>,
    ) -> Self {
        let n = C::BlockSize::to_usize();
        let mut nonce = nonce.clone();
        let block = GenericArray::from_mut_slice(&mut nonce[..n]);
        cipher.encrypt_block(block);
        Self {
            cipher,
            nonce,
            pos: 0,
            _p: Default::default(),
        }
    }
}

impl<C, Z, S> NewStreamCipher for GostOfb<C, Z, S>
where
    C: BlockCipher + NewBlockCipher,
    S: Unsigned + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Z: Mul<C::BlockSize> + IsGreater<U0>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
{
    type KeySize = C::KeySize;
    type NonceSize = <Z as Mul<C::BlockSize>>::Output;

    fn new(
        key: &GenericArray<u8, Self::KeySize>,
        nonce: &GenericArray<u8, Self::NonceSize>,
    ) -> Self {
        Self::from_block_cipher(C::new(key), nonce)
    }

    // TODO re-define new_var
}

impl<C, Z, S> SyncStreamCipher for GostOfb<C, Z, S>
where
    C: BlockCipher + NewBlockCipher,
    S: Unsigned + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Z: Mul<C::BlockSize> + IsGreater<U0>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
{
    fn try_apply_keystream(&mut self, mut data: &mut [u8]) -> Result<(), LoopError> {
        let s = S::to_usize();

        if data.len() >= s - self.pos {
            let (l, r) = { data }.split_at_mut(s - self.pos);
            data = r;
            xor(l, &self.nonce[self.pos..s]);
            self.cipher.encrypt_block(&mut self.block);
        } else {
            let n = data.len();
            xor(data, &self.block[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(());
        }

        /*
        let mut block = self.block.clone();
        while data.len() >= bs {
            let (l, r) = { data }.split_at_mut(bs);
            data = r;
            xor(l, &block);
            self.cipher.encrypt_block(&mut block);
        }
        self.block = block;
        let n = data.len();
        self.pos = n;
        xor(data, &self.block[..n]);
        */
        Ok(())
    }
}