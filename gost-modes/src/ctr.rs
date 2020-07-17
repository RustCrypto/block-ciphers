use crate::utils::xor;
use crate::errors::InvalidS;
use block_modes::block_cipher::{Block, BlockCipher, NewBlockCipher};
use core::convert::TryInto;
use core::ops::{Div, Rem};
use generic_array::typenum::type_operators::{IsEqual, IsLessOrEqual};
use generic_array::typenum::{Mod, Quot, Unsigned, U0, U2, U255, U8};
use generic_array::{ArrayLength, GenericArray};
use stream_cipher::{FromBlockCipher, LoopError, SyncStreamCipher};

/// Counter (CTR) block mode instance as defined in GOST R 34.13-2015.
#[derive(Clone)]
pub struct GostCtr<C>
where
    C: BlockCipher + NewBlockCipher,
    C::BlockSize: Div<U8> + Rem<U8> + Div<U2> + IsLessOrEqual<U255>,
    Mod<C::BlockSize, U8>: IsEqual<U0>,
    Quot<C::BlockSize, U8>: ArrayLength<u64>,
    Quot<C::BlockSize, U2>: ArrayLength<u8>,
{
    cipher: C,
    block: Block<C>,
    ctr: GenericArray<u64, Quot<C::BlockSize, U8>>,
    pos: u8,
    s: u8,
}

impl<C> GostCtr<C>
where
    C: BlockCipher + NewBlockCipher,
    C::BlockSize: Div<U8> + Rem<U8> + Div<U2> + IsLessOrEqual<U255>,
    Mod<C::BlockSize, U8>: IsEqual<U0>,
    Quot<C::BlockSize, U8>: ArrayLength<u64>,
    Quot<C::BlockSize, U2>: ArrayLength<u8>,
{
    /// Set number of block bytes used for message encryption.
    ///
    /// This method should be only used right after cipher initialization,
    /// before any data processing.
    pub fn set_s(&mut self, s: u8) -> Result<(), InvalidS> {
        if s > 0 && s <= C::BlockSize::U8 {
            self.s = s;
            Ok(())
        } else {
            Err(InvalidS)
        }
    }

    fn gen_block(&mut self) {
        for (c, v) in self.block.chunks_mut(8).zip(self.ctr.iter()) {
            c.copy_from_slice(&v.to_be_bytes());
        }
        self.cipher.encrypt_block(&mut self.block);
    }

    fn next_block(&mut self) {
        let mut carry = true;
        for v in self.ctr.iter_mut().rev() {
            if carry {
                let (t, f) = (*v).overflowing_add(1);
                *v = t;
                carry = f;
            }
        }
        self.gen_block();
    }
}

impl<C> FromBlockCipher for GostCtr<C>
where
    C: BlockCipher + NewBlockCipher,
    C::BlockSize: Div<U8> + Rem<U8> + Div<U2> + IsLessOrEqual<U255>,
    Mod<C::BlockSize, U8>: IsEqual<U0>,
    Quot<C::BlockSize, U8>: ArrayLength<u64>,
    Quot<C::BlockSize, U2>: ArrayLength<u8>,
{
    type BlockCipher = C;
    type NonceSize = Quot<<C as BlockCipher>::BlockSize, U2>;

    fn from_block_cipher(cipher: C, nonce: &GenericArray<u8, Self::NonceSize>) -> Self {
        let mut ctr = GenericArray::<u64, Quot<C::BlockSize, U8>>::default();

        for (c, n) in ctr.iter_mut().zip(nonce.chunks(8)) {
            *c = match n.len() {
                8 => u64::from_be_bytes(n.try_into().unwrap()),
                4 => (u32::from_be_bytes(n.try_into().unwrap()) as u64) << 32,
                _ => unreachable!(),
            };
        }

        let block = Default::default();

        let mut s = Self {
            cipher,
            block,
            ctr,
            pos: 0,
            s: C::BlockSize::U8,
        };
        s.gen_block();
        s
    }
}

impl<C> SyncStreamCipher for GostCtr<C>
where
    C: BlockCipher + NewBlockCipher,
    C::BlockSize: Div<U8> + Rem<U8> + Div<U2> + IsLessOrEqual<U255>,
    Mod<C::BlockSize, U8>: IsEqual<U0>,
    Quot<C::BlockSize, U8>: ArrayLength<u64>,
    Quot<C::BlockSize, U2>: ArrayLength<u8>,
{
    fn try_apply_keystream(&mut self, mut data: &mut [u8]) -> Result<(), LoopError> {
        let s = self.s as usize;
        let pos = self.pos as usize;

        if data.len() < s - pos {
            let n = data.len();
            xor(data, &self.block[pos..pos + n]);
            self.pos += n as u8;
            return Ok(());
        } else if pos != 0 {
            let (l, r) = { data }.split_at_mut(s - pos);
            data = r;
            xor(l, &self.block[pos..s]);
            self.pos = 0;
            self.next_block()
        }

        let mut iter = data.chunks_exact_mut(s);
        for chunk in &mut iter {
            xor(chunk, &self.block[..s]);
            self.next_block();
        }
        let rem = iter.into_remainder();
        xor(rem, &self.block[..rem.len()]);
        self.pos = rem.len() as u8;

        Ok(())
    }
}
