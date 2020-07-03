use crate::utils::xor;
use block_modes::block_cipher::{Block, BlockCipher, NewBlockCipher};
use core::marker::PhantomData;
use core::ops::Mul;
use generic_array::typenum::type_operators::{IsGreater, IsLessOrEqual};
use generic_array::typenum::{Prod, Unsigned, U0, U1, U255};
use generic_array::{ArrayLength, GenericArray};
use stream_cipher::{LoopError, NewStreamCipher, SyncStreamCipher};

/// Output feedback (OFB) block mode instance as defined in GOST R 34.13-2015.
///
/// Type parameters:
/// - `C`: block cipher.
/// - `Z`: nonce length in block sizes. Default: 1.
/// - `S`: number of block bytes used for message encryption. Default: block size.
///
/// With default parameters this mode is fully equivalent to the `Ofb` mode defined
/// in the `block-modes` crate.
#[derive(Clone)]
pub struct GostOfb<C, Z = U1, S = <C as BlockCipher>::BlockSize>
where
    C: BlockCipher + NewBlockCipher,
    C::BlockSize: IsLessOrEqual<U255>,
    S: Unsigned + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Z: ArrayLength<Block<C>> + Unsigned + Mul<C::BlockSize> + IsGreater<U0> + IsLessOrEqual<U255>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
{
    cipher: C,
    state: GenericArray<Block<C>, Z>,
    block_pos: u8,
    pos: u8,
    _p: PhantomData<(S, Z)>,
}

// TODO: replace with FromBlockCipher trait impl
impl<C, Z, S> GostOfb<C, Z, S>
where
    C: BlockCipher + NewBlockCipher,
    C::BlockSize: IsLessOrEqual<U255>,
    S: Unsigned + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Z: ArrayLength<Block<C>> + Unsigned + Mul<C::BlockSize> + IsGreater<U0> + IsLessOrEqual<U255>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
{
    pub fn from_block_cipher(
        cipher: C,
        nonce: &GenericArray<u8, <Self as NewStreamCipher>::NonceSize>,
    ) -> Self {
        let bs = C::BlockSize::to_usize();
        let mut state: GenericArray<Block<C>, Z> = Default::default();
        for (chunk, block) in nonce.chunks_exact(bs).zip(state.iter_mut()) {
            let mut t = GenericArray::clone_from_slice(chunk);
            cipher.encrypt_block(&mut t);
            *block = t;
        }

        Self {
            cipher,
            state,
            block_pos: 0,
            pos: 0,
            _p: Default::default(),
        }
    }
}

impl<C, Z, S> NewStreamCipher for GostOfb<C, Z, S>
where
    C: BlockCipher + NewBlockCipher,
    C::BlockSize: IsLessOrEqual<U255>,
    S: Unsigned + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Z: ArrayLength<Block<C>> + Unsigned + Mul<C::BlockSize> + IsGreater<U0> + IsLessOrEqual<U255>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
{
    type KeySize = C::KeySize;
    type NonceSize = Prod<Z, C::BlockSize>;

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
    C::BlockSize: IsLessOrEqual<U255>,
    S: Unsigned + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Z: ArrayLength<Block<C>> + Unsigned + Mul<C::BlockSize> + IsGreater<U0> + IsLessOrEqual<U255>,
    Prod<Z, C::BlockSize>: ArrayLength<u8>,
{
    fn try_apply_keystream(&mut self, mut data: &mut [u8]) -> Result<(), LoopError> {
        let s = S::USIZE;
        let pos = self.pos as usize;
        let block_pos = self.block_pos as usize;

        if data.len() < s - pos {
            let n = data.len();
            xor(data, &self.state[block_pos][pos..pos + n]);
            self.pos += n as u8;
            return Ok(());
        } else if pos != 0 {
            let (l, r) = { data }.split_at_mut(s - pos);
            data = r;
            xor(l, &self.state[block_pos][pos..s]);
            self.pos = 0;
            self.cipher
                .encrypt_block(&mut self.state[self.block_pos as usize]);
            self.block_pos = (self.block_pos + 1) % Z::U8;
        }

        let mut iter = data.chunks_exact_mut(s);
        for chunk in &mut iter {
            xor(chunk, &self.state[self.block_pos as usize][..s]);
            self.cipher
                .encrypt_block(&mut self.state[self.block_pos as usize]);
            self.block_pos = (self.block_pos + 1) % Z::U8;
        }
        let rem = iter.into_remainder();
        xor(rem, &self.state[self.block_pos as usize][..rem.len()]);
        self.pos += rem.len() as u8;

        Ok(())
    }
}
