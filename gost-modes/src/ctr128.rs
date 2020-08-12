use crate::utils::xor;
use block_modes::block_cipher::{Block, BlockCipher, NewBlockCipher};
use core::marker::PhantomData;
use generic_array::typenum::type_operators::{IsGreater, IsLessOrEqual};
use generic_array::typenum::{Unsigned, U0, U16, U8};
use generic_array::{ArrayLength, GenericArray};
use stream_cipher::{FromBlockCipher, LoopError, SyncStreamCipher, SyncStreamCipherSeek};

/// Counter (CTR) mode for 128-bit block ciphers as defined in GOST R 34.13-2015.
///
/// Type parameters:
/// - `C`: block cipher.
/// - `S`: number of block bytes used for message encryption. Default: block size.
#[derive(Clone)]
pub struct GostCtr128<C, S = <C as BlockCipher>::BlockSize>
where
    C: BlockCipher<BlockSize = U16> + NewBlockCipher,
    C::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
    S: ArrayLength<u8> + Unsigned + IsGreater<U0> + IsLessOrEqual<U16>,
{
    cipher: C,
    nonce: u64,
    ctr: u64,
    block: GenericArray<u8, S>,
    pos: u8,
    _p: PhantomData<S>,
}

impl<C, S> GostCtr128<C, S>
where
    C: BlockCipher<BlockSize = U16> + NewBlockCipher,
    C::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
    S: ArrayLength<u8> + Unsigned + IsGreater<U0> + IsLessOrEqual<U16>,
{
    fn gen_block(&mut self) {
        let mut block: Block<C> = Default::default();
        block[..8].copy_from_slice(&self.nonce.to_be_bytes());
        block[8..].copy_from_slice(&self.ctr.to_be_bytes());
        self.cipher.encrypt_block(&mut block);
        self.block.copy_from_slice(&block[..S::USIZE]);
    }

    fn next_block(&mut self) -> Result<(), LoopError> {
        self.ctr = self.ctr.checked_add(1).ok_or(LoopError)?;
        self.gen_block();
        Ok(())
    }
}

impl<C, S> FromBlockCipher for GostCtr128<C, S>
where
    C: BlockCipher<BlockSize = U16> + NewBlockCipher,
    C::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
    S: ArrayLength<u8> + Unsigned + IsGreater<U0> + IsLessOrEqual<U16>,
{
    type BlockCipher = C;
    type NonceSize = U8;

    fn from_block_cipher(cipher: C, nonce: &GenericArray<u8, U8>) -> Self {
        let mut s = Self {
            cipher,
            nonce: u64::from_be_bytes(*nonce.as_ref()),
            ctr: 0,
            block: Default::default(),
            pos: 0,
            _p: Default::default(),
        };
        s.gen_block();
        s
    }
}

impl<C, S> SyncStreamCipher for GostCtr128<C, S>
where
    C: BlockCipher<BlockSize = U16> + NewBlockCipher,
    C::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
    S: ArrayLength<u8> + Unsigned + IsGreater<U0> + IsLessOrEqual<U16>,
{
    fn try_apply_keystream(&mut self, mut data: &mut [u8]) -> Result<(), LoopError> {
        let s = self.block.len();
        let pos = self.pos as usize;

        if data.len() < s - pos {
            let n = data.len();
            xor(data, &self.block[pos..pos + n]);
            self.pos += n as u8;
            return Ok(());
        } else if pos != 0 {
            let (l, r) = { data }.split_at_mut(s - pos);
            data = r;
            xor(l, &self.block[pos..]);
            self.next_block()?;
        }

        let mut iter = data.chunks_exact_mut(s);
        for chunk in &mut iter {
            xor(chunk, &self.block);
            self.next_block()?;
        }
        let rem = iter.into_remainder();
        xor(rem, &self.block[..rem.len()]);
        self.pos = rem.len() as u8;

        Ok(())
    }
}

impl<C, S> SyncStreamCipherSeek for GostCtr128<C, S>
where
    C: BlockCipher<BlockSize = U16> + NewBlockCipher,
    C::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
    S: ArrayLength<u8> + Unsigned + IsGreater<U0> + IsLessOrEqual<U16>,
{
    fn current_pos(&self) -> u64 {
        self.ctr * S::U64 + (self.pos as u64)
    }

    fn seek(&mut self, pos: u64) {
        self.ctr = pos / S::U64;
        self.pos = (pos % S::U64) as u8;
        self.gen_block();
    }
}
