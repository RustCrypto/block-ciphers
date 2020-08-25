use crate::utils::xor;
use block_modes::block_cipher::{Block, BlockCipher, NewBlockCipher};
use generic_array::typenum::type_operators::{IsGreater, IsLessOrEqual};
use generic_array::typenum::{Unsigned, U0, U16, U8};
use generic_array::{ArrayLength, GenericArray};
use stream_cipher::{
    FromBlockCipher, LoopError, SyncStreamCipher, SyncStreamCipherSeek, OverflowError, SeekNum,
};

/// Counter (CTR) mode of operation for 128-bit block ciphers as defined in
/// GOST R 34.13-2015
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
}

impl<C, S> GostCtr128<C, S>
where
    C: BlockCipher<BlockSize = U16> + NewBlockCipher,
    C::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
    S: ArrayLength<u8> + Unsigned + IsGreater<U0> + IsLessOrEqual<U16>,
{
    fn gen_block(&self, ctr: u64) -> GenericArray<u8, S> {
        let mut block: Block<C> = Default::default();
        block[..8].copy_from_slice(&self.nonce.to_be_bytes());
        block[8..].copy_from_slice(&ctr.to_be_bytes());
        self.cipher.encrypt_block(&mut block);
        let mut res: GenericArray<u8, S> = Default::default();
        res.copy_from_slice(&block[..S::USIZE]);
        res
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
        Self {
            cipher,
            nonce: u64::from_be_bytes(*nonce.as_ref()),
            ctr: 0,
            block: Default::default(),
            pos: 0,
        }
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
        let mut ctr = self.ctr;

        if pos != 0 {
            if data.len() < s - pos {
                let n = data.len();
                xor(data, &self.block[pos..pos + n]);
                self.pos += n as u8;
                return Ok(());
            } else if pos != 0 {
                let (l, r) = { data }.split_at_mut(s - pos);
                data = r;
                xor(l, &self.block[pos..]);
                ctr += 1;
            }
        }

        let mut iter = data.chunks_exact_mut(s);
        for chunk in &mut iter {
            xor(chunk, &self.gen_block(ctr));
            ctr += 1;
        }
        let rem = iter.into_remainder();
        self.pos = rem.len() as u8;
        self.ctr = ctr;
        if !rem.is_empty() {
            self.block = self.gen_block(ctr);
            xor(rem, &self.block[..rem.len()]);
        }

        Ok(())
    }
}

impl<C, S> SyncStreamCipherSeek for GostCtr128<C, S>
where
    C: BlockCipher<BlockSize = U16> + NewBlockCipher,
    C::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
    S: ArrayLength<u8> + Unsigned + IsGreater<U0> + IsLessOrEqual<U16>,
{
    fn try_current_pos<T: SeekNum>(&self) -> Result<T, OverflowError> {
        T::from_block_byte(self.ctr, self.pos, S::U8)
    }

    fn try_seek<T: SeekNum>(&mut self, pos: T) -> Result<(), LoopError> {
        let res = pos.to_block_byte(S::U8)?;
        self.ctr = res.0;
        self.pos = res.1;
        if self.pos != 0 {
            self.block = self.gen_block(res.0);
        }
        Ok(())
    }
}
