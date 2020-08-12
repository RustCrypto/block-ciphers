use crate::utils::{xor_set1, xor_set2};
use block_modes::block_cipher::{Block, BlockCipher, NewBlockCipher};
use core::marker::PhantomData;
use core::ops::Sub;
use generic_array::typenum::type_operators::{IsGreater, IsGreaterOrEqual, IsLessOrEqual};
use generic_array::typenum::{Diff, Unsigned, U0, U255};
use generic_array::{ArrayLength, GenericArray};
use stream_cipher::{FromBlockCipher, StreamCipher};

type BlockSize<C> = <C as BlockCipher>::BlockSize;

type Tail<C, M> = GenericArray<u8, Diff<M, <C as BlockCipher>::BlockSize>>;

/// Cipher feedback (CFB) mode of operation as defined in GOST R 34.13-2015
///
/// Type parameters:
/// - `C`: block cipher.
/// - `M`: nonce length in bytes. Default: block size.
/// - `S`: number of block bytes used for message encryption. Default: block size.
///
/// With default parameters this mode is fully equivalent to the `Cfb` mode defined
/// in the `cfb-mode` crate.
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
    tail: Tail<C, M>,
    pos: u8,
    _p: PhantomData<S>,
}

impl<C, M, S> GostCfb<C, M, S>
where
    C: BlockCipher + NewBlockCipher,
    C::BlockSize: IsLessOrEqual<U255>,
    M: Unsigned + ArrayLength<u8> + IsGreaterOrEqual<C::BlockSize> + Sub<C::BlockSize>,
    S: Unsigned + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Diff<M, C::BlockSize>: ArrayLength<u8>,
{
    // chunk has length of `s`
    fn gen_block(&mut self) {
        let s = S::to_usize();
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
            let mut tail: Tail<C, M> = Default::default();
            tail[..d].copy_from_slice(&self.tail[s..]);
            tail[d..].copy_from_slice(&self.block);
            self.block = GenericArray::clone_from_slice(&self.tail[..s]);
            self.tail = tail;
        }
        self.cipher.encrypt_block(&mut self.block);
    }
}

impl<C, M, S> FromBlockCipher for GostCfb<C, M, S>
where
    C: BlockCipher + NewBlockCipher,
    C::BlockSize: IsLessOrEqual<U255>,
    M: Unsigned + ArrayLength<u8> + IsGreaterOrEqual<C::BlockSize> + Sub<C::BlockSize>,
    S: Unsigned + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Diff<M, C::BlockSize>: ArrayLength<u8>,
{
    type BlockCipher = C;
    type NonceSize = M;

    fn from_block_cipher(cipher: C, nonce: &GenericArray<u8, M>) -> Self {
        let bs = C::BlockSize::USIZE;
        let mut block = GenericArray::clone_from_slice(&nonce[..bs]);
        cipher.encrypt_block(&mut block);
        let tail = GenericArray::clone_from_slice(&nonce[bs..]);
        Self {
            cipher,
            block,
            tail,
            pos: 0,
            _p: Default::default(),
        }
    }
}

impl<C, M, S> StreamCipher for GostCfb<C, M, S>
where
    C: BlockCipher + NewBlockCipher,
    C::BlockSize: IsLessOrEqual<U255>,
    M: Unsigned + ArrayLength<u8> + IsGreaterOrEqual<C::BlockSize> + Sub<C::BlockSize>,
    S: Unsigned + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Diff<M, C::BlockSize>: ArrayLength<u8>,
{
    fn encrypt(&mut self, mut data: &mut [u8]) {
        let s = S::USIZE;
        let pos = self.pos as usize;

        if data.len() < s - pos {
            let n = data.len();
            xor_set1(data, &mut self.block[pos..pos + n]);
            self.pos += n as u8;
            return;
        } else if pos != 0 {
            let (l, r) = { data }.split_at_mut(s - pos);
            data = r;
            xor_set1(l, &mut self.block[pos..s]);
            self.gen_block()
        }

        let mut iter = data.chunks_exact_mut(s);
        for chunk in &mut iter {
            xor_set1(chunk, &mut self.block[..s]);
            self.gen_block();
        }
        let rem = iter.into_remainder();
        xor_set1(rem, &mut self.block[..rem.len()]);
        self.pos = rem.len() as u8;
    }

    fn decrypt(&mut self, mut data: &mut [u8]) {
        let s = S::USIZE;
        let pos = self.pos as usize;

        if data.len() < s - pos {
            let n = data.len();
            xor_set2(data, &mut self.block[pos..pos + n]);
            self.pos += n as u8;
            return;
        } else if pos != 0 {
            let (l, r) = { data }.split_at_mut(s - pos);
            data = r;
            xor_set2(l, &mut self.block[pos..s]);
            self.gen_block()
        }

        let mut iter = data.chunks_exact_mut(s);
        for chunk in &mut iter {
            xor_set2(chunk, &mut self.block[..s]);
            self.gen_block();
        }
        let rem = iter.into_remainder();
        xor_set2(rem, &mut self.block[..rem.len()]);
        self.pos = rem.len() as u8;
    }
}
