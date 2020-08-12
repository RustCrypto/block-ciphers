use crate::utils::{xor_set1, xor_set2};
use block_modes::block_cipher::{Block, BlockCipher, NewBlockCipher};
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
    S: Unsigned + ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Diff<M, C::BlockSize>: ArrayLength<u8>,
{
    cipher: C,
    block: GenericArray<u8, S>,
    tail: Tail<C, M>,
    pos: u8,
}

impl<C, M, S> GostCfb<C, M, S>
where
    C: BlockCipher + NewBlockCipher,
    C::BlockSize: IsLessOrEqual<U255>,
    M: Unsigned + ArrayLength<u8> + IsGreaterOrEqual<C::BlockSize> + Sub<C::BlockSize>,
    S: Unsigned + ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Diff<M, C::BlockSize>: ArrayLength<u8>,
{
    // chunk has length of `s`
    fn gen_block(&mut self) {
        let s = S::USIZE;
        let ts = self.tail.len();
        let mut block: Block<C> = Default::default();
        if ts <= s {
            let d = s - ts;
            block[..ts].copy_from_slice(&self.tail);
            block[ts..].copy_from_slice(&self.block[..d]);
            self.tail = GenericArray::clone_from_slice(&self.block[d..]);
        } else {
            let d = ts - s;
            let mut tail: Tail<C, M> = Default::default();
            tail[..d].copy_from_slice(&self.tail[s..]);
            tail[d..].copy_from_slice(&self.block);
            block = GenericArray::clone_from_slice(&self.tail[..s]);
            self.tail = tail;
        }
        self.cipher.encrypt_block(&mut block);
        self.block.copy_from_slice(&block[..s]);
    }
}

impl<C, M, S> FromBlockCipher for GostCfb<C, M, S>
where
    C: BlockCipher + NewBlockCipher,
    C::BlockSize: IsLessOrEqual<U255>,
    M: Unsigned + ArrayLength<u8> + IsGreaterOrEqual<C::BlockSize> + Sub<C::BlockSize>,
    S: Unsigned + ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
    Diff<M, C::BlockSize>: ArrayLength<u8>,
{
    type BlockCipher = C;
    type NonceSize = M;

    fn from_block_cipher(cipher: C, nonce: &GenericArray<u8, M>) -> Self {
        let bs = C::BlockSize::USIZE;
        let mut full_block = Block::<C>::clone_from_slice(&nonce[..bs]);
        cipher.encrypt_block(&mut full_block);
        let block = GenericArray::clone_from_slice(&full_block[..S::USIZE]);
        let tail = GenericArray::clone_from_slice(&nonce[bs..]);
        Self {
            cipher,
            block,
            tail,
            pos: 0,
        }
    }
}

impl<C, M, S> StreamCipher for GostCfb<C, M, S>
where
    C: BlockCipher + NewBlockCipher,
    C::BlockSize: IsLessOrEqual<U255>,
    M: Unsigned + ArrayLength<u8> + IsGreaterOrEqual<C::BlockSize> + Sub<C::BlockSize>,
    S: Unsigned + ArrayLength<u8> + IsGreater<U0> + IsLessOrEqual<C::BlockSize>,
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
            xor_set2(l, &mut self.block[pos..]);
            self.gen_block()
        }

        let mut iter = data.chunks_exact_mut(s);
        for chunk in &mut iter {
            xor_set2(chunk, &mut self.block);
            self.gen_block();
        }
        let rem = iter.into_remainder();
        xor_set2(rem, &mut self.block[..rem.len()]);
        self.pos = rem.len() as u8;
    }
}
