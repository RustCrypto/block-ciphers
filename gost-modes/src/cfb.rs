use crate::utils::xor2;
use generic_array::{ArrayLength, GenericArray};
use generic_array::typenum::{U0, U255, Unsigned, Diff,};
use generic_array::typenum::type_operators::{IsLessOrEqual, IsGreater, IsGreaterOrEqual};
use block_modes::block_cipher::{BlockCipher, NewBlockCipher, Block};
use stream_cipher::{NewStreamCipher, SyncStreamCipher, LoopError};
use core::marker::PhantomData;
use core::ops::Sub;

type BlockSize<C> = <C as BlockCipher>::BlockSize;

/// Cipher feedback (CFB) block mode instance as defined in GOST R 34.13-2015.
///
/// Type parameters:
/// - `C`: block cipher.
/// - `M`: nonce length in bytes. Default: block size.
/// - `S`: number of block bytes used for message encryption. Default: block size.
/// 
/// With default parameters this mode is fully equivalent to the `Cfb` mode defined
/// in the `block-modes` crate.
#[derive(Clone)]
pub struct GostCfb<C, M = BlockSize<C>, S = BlockSize<C>>
where
    C: BlockCipher + NewBlockCipher,
    C::BlockSize: IsLessOrEqual<U255>,
    M: Unsigned + ArrayLength<u8> + IsGreaterOrEqual<C::BlockSize> + Sub<C::BlockSize>,
    S: Unsigned + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Diff<M, C::BlockSize>: ArrayLength<u8>,
{
    cipher: C,
    block: Block<C>,
    tail: GenericArray<u8, Diff<M, C::BlockSize>>,
    pos: u8,
    _p: PhantomData<(M, S)>,
}

impl<C, M, S> GostCfb<C, M, S>
where
    C: BlockCipher + NewBlockCipher,
    C::BlockSize: IsLessOrEqual<U255>,
    M: Unsigned + ArrayLength<u8> + IsGreaterOrEqual<C::BlockSize> + Sub<C::BlockSize>,
    S: Unsigned + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Diff<M, C::BlockSize>: ArrayLength<u8>,
{
    pub fn from_block_cipher(
        cipher: C,
        nonce: &GenericArray<u8, M>,
    ) -> Self {
        let bs = C::BlockSize::USIZE;
        let mut block = GenericArray::clone_from_slice(&nonce[..bs]);
        cipher.encrypt_block(&mut block);
        let tail = GenericArray::clone_from_slice(&nonce[bs..]);
        Self { cipher, block, tail, pos: 0, _p: Default::default() }
    }

    fn gen_block(&mut self) {
        let s = S::USIZE;
        let ts = self.tail.len();
        if ts <= s {
            let d = s - ts;
            let mut block = Block::<C>::default();
            block[..ts].copy_from_slice(&self.tail);
            block[ts..].copy_from_slice(&self.block[..d]);
            self.tail = GenericArray::clone_from_slice(&self.block[d..]);
            self.block = block;
        } else {
            let d = ts - s;
            let mut tail = GenericArray::<u8, Diff<M, C::BlockSize>>::default();
            tail[..d].copy_from_slice(&self.tail[s..]);
            tail[d..].copy_from_slice(&self.block);
            self.block = GenericArray::clone_from_slice(&self.tail[..s]);
            self.tail = tail;
        }
        self.cipher.encrypt_block(&mut self.block);
    }
}

impl<C, M, S> NewStreamCipher for GostCfb<C, M, S>
where
    C: BlockCipher + NewBlockCipher,
    C::BlockSize: IsLessOrEqual<U255>,
    M: Unsigned + ArrayLength<u8> + IsGreaterOrEqual<C::BlockSize> + Sub<C::BlockSize>,
    S: Unsigned + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Diff<M, C::BlockSize>: ArrayLength<u8>,
{
    type KeySize = C::KeySize;
    type NonceSize = M;

    fn new(
        key: &GenericArray<u8, Self::KeySize>,
        nonce: &GenericArray<u8, Self::NonceSize>,
    ) -> Self {
        Self::from_block_cipher(C::new(key), nonce)
    }
}

impl<C, M, S> SyncStreamCipher for GostCfb<C, M, S>
where
    C: BlockCipher + NewBlockCipher,
    C::BlockSize: IsLessOrEqual<U255>,
    M: Unsigned + ArrayLength<u8> + IsGreaterOrEqual<C::BlockSize> + Sub<C::BlockSize>,
    S: Unsigned + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Diff<M, C::BlockSize>: ArrayLength<u8>,
{
    fn try_apply_keystream(&mut self, mut data: &mut [u8]) -> Result<(), LoopError> {
        let s = S::USIZE;
        let pos = self.pos as usize;

        if data.len() < s - pos {
            let n = data.len();
            xor2(data, &mut self.block[pos..pos + n]);
            self.pos += n as u8;
            return Ok(());
        } else if pos != 0 {
            let (l, r) = { data }.split_at_mut(s - pos);
            data = r;
            xor2(l, &mut self.block[pos..s]);
            self.pos = 0;
            self.gen_block()
        }

        let mut iter = data.chunks_exact_mut(s);
        for chunk in &mut iter {
            xor2(chunk, &mut self.block[..s]);
            self.gen_block();
        }
        let rem = iter.into_remainder();
        xor2(rem, &mut self.block[..rem.len()]);
        self.pos = rem.len() as u8;

        Ok(())
    }
}
