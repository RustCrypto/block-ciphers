use core::{
    marker::PhantomData,
    ops::{Add, Div, Mul, Sub},
};

use cipher::{
    generic_array::ArrayLength,
    inout::InOut,
    typenum::{Diff, IsLess, Le, NonZero, Sum, Unsigned, U1, U12, U16, U2, U256},
    AlgorithmName, Block, BlockBackend, BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser,
    KeyInit, KeySizeUser, ParBlocksSizeUser,
};

use crate::core::{
    BlockSize, ExpandedKeyTable, ExpandedKeyTableSize, KeyAsWordsSize, Word, RC5 as RC5Trait,
};

pub struct RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArrayLength<u8>,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArrayLength<W>,
{
    key_table: ExpandedKeyTable<W, R>,
    _key_size: PhantomData<B>,
}

impl<W, R, B> RC5Trait<W, R, B> for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArrayLength<u8>,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArrayLength<W>,
    // Key range
    B: ArrayLength<u8>,
    B: IsLess<U256>,
    Le<B, U256>: NonZero,
    // KeyAsWordsSize
    B: Add<W::Bytes>,
    Sum<B, W::Bytes>: Sub<U1>,
    Diff<Sum<B, W::Bytes>, U1>: Div<W::Bytes>,
    KeyAsWordsSize<W, B>: ArrayLength<W>,
{
}

impl<W, R, B> KeyInit for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArrayLength<u8>,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArrayLength<W>,
    // Key range
    B: ArrayLength<u8>,
    B: IsLess<U256>,
    Le<B, U256>: NonZero,
    // KeyAsWordsSize
    B: Add<W::Bytes>,
    Sum<B, W::Bytes>: Sub<U1>,
    Diff<Sum<B, W::Bytes>, U1>: Div<W::Bytes>,
    KeyAsWordsSize<W, B>: ArrayLength<W>,
{
    fn new(key: &cipher::Key<Self>) -> Self {
        Self {
            key_table: Self::substitute_key(key),
            _key_size: PhantomData,
        }
    }
}

impl<W, R, B> KeySizeUser for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArrayLength<u8>,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArrayLength<W>,
    B: ArrayLength<u8>,
{
    type KeySize = B;
}

impl<W, R, B> BlockCipher for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArrayLength<u8>,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArrayLength<W>,
{
}

impl<W, R, B> BlockSizeUser for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArrayLength<u8>,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArrayLength<W>,
{
    type BlockSize = BlockSize<W>;
}

impl<W, R, B> BlockEncrypt for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArrayLength<u8>,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArrayLength<W>,
    // Key range
    B: ArrayLength<u8>,
    B: IsLess<U256>,
    Le<B, U256>: NonZero,
    // KeyAsWordsSize
    B: Add<W::Bytes>,
    Sum<B, W::Bytes>: Sub<U1>,
    Diff<Sum<B, W::Bytes>, U1>: Div<W::Bytes>,
    KeyAsWordsSize<W, B>: ArrayLength<W>,
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
    BlockSize<W>: ArrayLength<u8>,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArrayLength<W>,
{
    enc_dec: &'a RC5<W, R, B>,
}
impl<'a, W, R, B> BlockSizeUser for RC5EncryptBackend<'a, W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArrayLength<u8>,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArrayLength<W>,
{
    type BlockSize = BlockSize<W>;
}

impl<'a, W, R, B> ParBlocksSizeUser for RC5EncryptBackend<'a, W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArrayLength<u8>,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArrayLength<W>,
{
    type ParBlocksSize = U1;
}

impl<'a, W, R, B> BlockBackend for RC5EncryptBackend<'a, W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArrayLength<u8>,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArrayLength<W>,
    // Key range
    B: ArrayLength<u8>,
    B: IsLess<U256>,
    Le<B, U256>: NonZero,
    // KeyAsWordsSize
    B: Add<W::Bytes>,
    Sum<B, W::Bytes>: Sub<U1>,
    Diff<Sum<B, W::Bytes>, U1>: Div<W::Bytes>,
    KeyAsWordsSize<W, B>: ArrayLength<W>,
{
    #[inline(always)]
    fn proc_block(&mut self, block: InOut<'_, '_, Block<Self>>) {
        let backend = self.enc_dec;
        RC5::<W, R, B>::encrypt(block, &backend.key_table)
    }
}

impl<W, R, B> BlockDecrypt for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArrayLength<u8>,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArrayLength<W>,
    // Key range
    B: ArrayLength<u8>,
    B: IsLess<U256>,
    Le<B, U256>: NonZero,
    // KeyAsWordsSize
    B: Add<W::Bytes>,
    Sum<B, W::Bytes>: Sub<U1>,
    Diff<Sum<B, W::Bytes>, U1>: Div<W::Bytes>,
    KeyAsWordsSize<W, B>: ArrayLength<W>,
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
    BlockSize<W>: ArrayLength<u8>,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArrayLength<W>,
{
    enc_dec: &'a RC5<W, R, B>,
}
impl<'a, W, R, B> BlockSizeUser for RC5DecryptBackend<'a, W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArrayLength<u8>,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArrayLength<W>,
{
    type BlockSize = BlockSize<W>;
}

impl<'a, W, R, B> ParBlocksSizeUser for RC5DecryptBackend<'a, W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArrayLength<u8>,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArrayLength<W>,
{
    type ParBlocksSize = U1;
}

impl<'a, W, R, B> BlockBackend for RC5DecryptBackend<'a, W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArrayLength<u8>,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArrayLength<W>,
    // Key range
    B: ArrayLength<u8>,
    B: IsLess<U256>,
    Le<B, U256>: NonZero,
    // KeyAsWordsSize
    B: Add<W::Bytes>,
    Sum<B, W::Bytes>: Sub<U1>,
    Diff<Sum<B, W::Bytes>, U1>: Div<W::Bytes>,
    KeyAsWordsSize<W, B>: ArrayLength<W>,
{
    #[inline(always)]
    fn proc_block(&mut self, block: InOut<'_, '_, Block<Self>>) {
        let backend = self.enc_dec;
        RC5::<W, R, B>::decrypt(block, &backend.key_table)
    }
}

impl<W, R, B> AlgorithmName for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArrayLength<u8>,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArrayLength<W>,
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

#[cfg(feature = "zeroize")]
impl<W, R, B> cipher::zeroize::ZeroizeOnDrop for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArrayLength<u8>,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArrayLength<W>,
{
}

#[cfg(feature = "zeroize")]
impl<W, R, B> Drop for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArrayLength<u8>,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArrayLength<W>,
{
    fn drop(&mut self) {
        cipher::zeroize::Zeroize::zeroize(&mut *self.key_table)
    }
}

pub type RC5_32_12_16 = RC5<u32, U12, U16>;
pub type RC5_32_16_16 = RC5<u32, U16, U16>;
