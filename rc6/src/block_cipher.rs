use core::ops::{Add, Div, Mul, Sub};

use cipher::{
    AlgorithmName, Block, BlockSizeUser, KeyInit, KeySizeUser, ParBlocksSizeUser,
    array::ArraySize,
    block::{
        BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt, BlockCipherEncBackend,
        BlockCipherEncClosure, BlockCipherEncrypt,
    },
    inout::InOut,
    typenum::{Diff, IsLess, Le, NonZero, Sum, U1, U2, U4, U8, U12, U16, U20, U24, U256, Unsigned},
};

use crate::core::{BlockSize, ExpandedKeyTableSize, KeyAsWordsSize, RC6, Word};

impl<W, R, B> KeyInit for RC6<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U4>,
    BlockSize<W>: ArraySize,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U2>,
    Sum<R, U2>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
    // Key range
    B: ArraySize,
    B: IsLess<U256>,
    Le<B, U256>: NonZero,
    // KeyAsWordsSize
    B: Add<W::Bytes>,
    Sum<B, W::Bytes>: Sub<U1>,
    Diff<Sum<B, W::Bytes>, U1>: Div<W::Bytes>,
    KeyAsWordsSize<W, B>: ArraySize,
{
    fn new(key: &cipher::Key<Self>) -> Self {
        Self::new(key)
    }
}

impl<W, R, B> KeySizeUser for RC6<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U4>,
    BlockSize<W>: ArraySize,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U2>,
    Sum<R, U2>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
    B: ArraySize,
{
    type KeySize = B;
}

impl<W, R, B> BlockSizeUser for RC6<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U4>,
    BlockSize<W>: ArraySize,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U2>,
    Sum<R, U2>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    type BlockSize = BlockSize<W>;
}

impl<W, R, B> BlockCipherEncrypt for RC6<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U4>,
    BlockSize<W>: ArraySize,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U2>,
    Sum<R, U2>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
    // Key range
    B: ArraySize,
    B: IsLess<U256>,
    Le<B, U256>: NonZero,
    // KeyAsWordsSize
    B: Add<W::Bytes>,
    Sum<B, W::Bytes>: Sub<U1>,
    Diff<Sum<B, W::Bytes>, U1>: Div<W::Bytes>,
    KeyAsWordsSize<W, B>: ArraySize,
{
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
        f.call(&RC6EncryptBackend { enc_dec: self })
    }
}

struct RC6EncryptBackend<'a, W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U4>,
    BlockSize<W>: ArraySize,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U2>,
    Sum<R, U2>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    enc_dec: &'a RC6<W, R, B>,
}
impl<W, R, B> BlockSizeUser for RC6EncryptBackend<'_, W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U4>,
    BlockSize<W>: ArraySize,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U2>,
    Sum<R, U2>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    type BlockSize = BlockSize<W>;
}

impl<W, R, B> ParBlocksSizeUser for RC6EncryptBackend<'_, W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U4>,
    BlockSize<W>: ArraySize,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U2>,
    Sum<R, U2>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    type ParBlocksSize = U1;
}

impl<W, R, B> BlockCipherEncBackend for RC6EncryptBackend<'_, W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U4>,
    BlockSize<W>: ArraySize,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U2>,
    Sum<R, U2>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
    // Key range
    B: ArraySize,
    B: IsLess<U256>,
    Le<B, U256>: NonZero,
    // KeyAsWordsSize
    B: Add<W::Bytes>,
    Sum<B, W::Bytes>: Sub<U1>,
    Diff<Sum<B, W::Bytes>, U1>: Div<W::Bytes>,
    KeyAsWordsSize<W, B>: ArraySize,
{
    #[inline(always)]
    fn encrypt_block(&self, block: InOut<'_, '_, Block<Self>>) {
        let backend = self.enc_dec;
        backend.encrypt(block)
    }
}

impl<W, R, B> BlockCipherDecrypt for RC6<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U4>,
    BlockSize<W>: ArraySize,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U2>,
    Sum<R, U2>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
    // Key range
    B: ArraySize,
    B: IsLess<U256>,
    Le<B, U256>: NonZero,
    // KeyAsWordsSize
    B: Add<W::Bytes>,
    Sum<B, W::Bytes>: Sub<U1>,
    Diff<Sum<B, W::Bytes>, U1>: Div<W::Bytes>,
    KeyAsWordsSize<W, B>: ArraySize,
{
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
        f.call(&RC6DecryptBackend { enc_dec: self })
    }
}

struct RC6DecryptBackend<'a, W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U4>,
    BlockSize<W>: ArraySize,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U2>,
    Sum<R, U2>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    enc_dec: &'a RC6<W, R, B>,
}
impl<W, R, B> BlockSizeUser for RC6DecryptBackend<'_, W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U4>,
    BlockSize<W>: ArraySize,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U2>,
    Sum<R, U2>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    type BlockSize = BlockSize<W>;
}

impl<W, R, B> ParBlocksSizeUser for RC6DecryptBackend<'_, W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U4>,
    BlockSize<W>: ArraySize,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U2>,
    Sum<R, U2>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    type ParBlocksSize = U1;
}

impl<W, R, B> BlockCipherDecBackend for RC6DecryptBackend<'_, W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U4>,
    BlockSize<W>: ArraySize,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U2>,
    Sum<R, U2>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
    // Key range
    B: ArraySize,
    B: IsLess<U256>,
    Le<B, U256>: NonZero,
    // KeyAsWordsSize
    B: Add<W::Bytes>,
    Sum<B, W::Bytes>: Sub<U1>,
    Diff<Sum<B, W::Bytes>, U1>: Div<W::Bytes>,
    KeyAsWordsSize<W, B>: ArraySize,
{
    #[inline(always)]
    fn decrypt_block(&self, block: InOut<'_, '_, Block<Self>>) {
        let backend = self.enc_dec;
        backend.decrypt(block)
    }
}

impl<W, R, B> AlgorithmName for RC6<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U4>,
    BlockSize<W>: ArraySize,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U2>,
    Sum<R, U2>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "RC6 - {}/{}/{}",
            core::any::type_name::<W>(),
            <R as Unsigned>::to_u8(),
            <R as Unsigned>::to_u8(),
        )
    }
}

pub type RC6_8_12_4 = RC6<u8, U12, U4>;
pub type RC6_16_16_8 = RC6<u16, U16, U8>;
pub type RC6_32_20_16 = RC6<u32, U20, U16>;
pub type RC6_64_24_24 = RC6<u64, U24, U24>;
