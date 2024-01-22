use core::ops::{Add, Div, Mul, Sub};

use cipher::{
    array::ArraySize,
    consts::*,
    crypto_common::BlockSizes,
    inout::InOut,
    typenum::{Diff, IsLess, Le, NonZero, Sum, Unsigned, U1, U2, U256},
    AlgorithmName, Block, BlockBackend, BlockCipher, BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser,
    KeyInit, KeySizeUser, ParBlocksSizeUser,
};

use crate::core::{BlockSize, ExpandedKeyTableSize, KeyAsWordsSize, Word, RC5};

impl<W, R, B> KeyInit for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: BlockSizes,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
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

impl<W, R, B> KeySizeUser for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: BlockSizes,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
    B: ArraySize,
{
    type KeySize = B;
}

impl<W, R, B> BlockCipher for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: BlockSizes,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
{
}

impl<W, R, B> BlockSizeUser for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: BlockSizes,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    type BlockSize = BlockSize<W>;
}

impl<W, R, B> BlockCipherEncrypt for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: BlockSizes,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
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
    fn encrypt_with_backend(&self, f: impl cipher::BlockClosure<BlockSize = Self::BlockSize>) {
        f.call(&mut RC5EncryptBackend { enc_dec: self })
    }
}

struct RC5EncryptBackend<'a, W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: BlockSizes,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    enc_dec: &'a RC5<W, R, B>,
}
impl<'a, W, R, B> BlockSizeUser for RC5EncryptBackend<'a, W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: BlockSizes,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    type BlockSize = BlockSize<W>;
}

impl<'a, W, R, B> ParBlocksSizeUser for RC5EncryptBackend<'a, W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: BlockSizes,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    type ParBlocksSize = U1;
}

impl<'a, W, R, B> BlockBackend for RC5EncryptBackend<'a, W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: BlockSizes,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
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
    fn proc_block(&mut self, block: InOut<'_, '_, Block<Self>>) {
        let backend = self.enc_dec;
        backend.encrypt(block)
    }
}

impl<W, R, B> BlockCipherDecrypt for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: BlockSizes,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
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
    fn decrypt_with_backend(&self, f: impl cipher::BlockClosure<BlockSize = Self::BlockSize>) {
        f.call(&mut RC5DecryptBackend { enc_dec: self })
    }
}

struct RC5DecryptBackend<'a, W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: BlockSizes,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    enc_dec: &'a RC5<W, R, B>,
}
impl<'a, W, R, B> BlockSizeUser for RC5DecryptBackend<'a, W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: BlockSizes,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    type BlockSize = BlockSize<W>;
}

impl<'a, W, R, B> ParBlocksSizeUser for RC5DecryptBackend<'a, W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: BlockSizes,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    type ParBlocksSize = U1;
}

impl<'a, W, R, B> BlockBackend for RC5DecryptBackend<'a, W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: BlockSizes,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
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
    fn proc_block(&mut self, block: InOut<'_, '_, Block<Self>>) {
        let backend = self.enc_dec;
        backend.decrypt(block)
    }
}

impl<W, R, B> AlgorithmName for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: BlockSizes,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "RC5 - {}/{}/{}",
            core::any::type_name::<W>(),
            <R as Unsigned>::to_u8(),
            <R as Unsigned>::to_u8(),
        )
    }
}

#[allow(dead_code)]
#[deprecated(since = "0.1.0", note = "use RC5<u16, U16, U8> instead.")]
pub type RC5_16_16_8 = RC5<u16, U16, U8>;
#[allow(dead_code)]
#[deprecated(since = "0.1.0", note = "use RC5<u32, U12, U16> instead.")]
pub type RC5_32_12_16 = RC5<u32, U12, U16>;
#[allow(dead_code)]
#[deprecated(since = "0.1.0", note = "use RC5<u32, U16, U16> instead.")]
pub type RC5_32_16_16 = RC5<u32, U16, U16>;
#[allow(dead_code)]
#[deprecated(since = "0.1.0", note = "use RC5<u64, U24, U24> instead.")]
pub type RC5_64_24_24 = RC5<u64, U24, U24>;
