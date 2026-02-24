//! Pure Rust implementation of the [RC5] block cipher.
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate implements only the low-level block cipher function, and is intended
//! for use for implementing higher-level constructions *only*. It is NOT
//! intended for direct use in applications.
//!
//! USE AT YOUR OWN RISK!
//!
//! [RC5]: https://en.wikipedia.org/wiki/RC5
#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

use cipher::{
    AlgorithmName, Array, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, KeyInit,
    KeySizeUser, ParBlocksSizeUser,
    array::ArraySize,
    consts::{U1, U2, U256},
    inout::InOut,
    typenum::{Diff, IsLess, Le, NonZero, Sum, Unsigned},
};
use core::{
    cmp::max,
    fmt,
    marker::PhantomData,
    ops::{Add, Div, Mul, Sub},
};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

mod primitives;

use primitives::{
    Block, BlockSize, ExpandedKeyTable, ExpandedKeyTableSize, Key, KeyAsWords, KeyAsWordsSize, Word,
};

/// RC5 block cipher instance.
#[derive(Clone)]
pub struct RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArraySize,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    key_table: ExpandedKeyTable<W, R>,
    _key_size: PhantomData<B>,
}

impl<W, R, B> RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArraySize,
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
    pub(crate) fn substitute_key(key: &Key<B>) -> ExpandedKeyTable<W, R> {
        let key_as_words = Self::key_into_words(key);
        let expanded_key_table = Self::initialize_expanded_key_table();

        Self::mix_in(expanded_key_table, key_as_words)
    }

    fn key_into_words(key: &Key<B>) -> KeyAsWords<W, B> {
        // can be uninitialized
        let mut key_as_words: Array<W, KeyAsWordsSize<W, B>> = Array::default();

        for i in (0..B::USIZE).rev() {
            key_as_words[i / W::Bytes::USIZE] =
                key_as_words[i / W::Bytes::USIZE].rotate_left(W::EIGHT) + key[i].into();
            // no need for wrapping addition since we are adding a byte sized uint onto an uint with its lsb byte zeroed
        }

        key_as_words
    }

    fn initialize_expanded_key_table() -> ExpandedKeyTable<W, R> {
        // must be zero initialized
        let mut expanded_key_table: Array<W, ExpandedKeyTableSize<R>> = Array::from_fn(|_| W::ZERO);

        expanded_key_table[0] = W::P;
        for i in 1..expanded_key_table.len() {
            expanded_key_table[i] = expanded_key_table[i - 1].wrapping_add(W::Q);
        }

        expanded_key_table
    }

    fn mix_in(
        mut key_table: ExpandedKeyTable<W, R>,
        mut key_as_words: KeyAsWords<W, B>,
    ) -> ExpandedKeyTable<W, R> {
        let (mut expanded_key_index, mut key_as_words_index) = (0, 0);
        let (mut a, mut b) = (W::ZERO, W::ZERO);

        for _ in 0..3 * max(key_as_words.len(), key_table.len()) {
            key_table[expanded_key_index] = key_table[expanded_key_index]
                .wrapping_add(a)
                .wrapping_add(b)
                .rotate_left(W::THREE);

            a = key_table[expanded_key_index];

            key_as_words[key_as_words_index] = key_as_words[key_as_words_index]
                .wrapping_add(a)
                .wrapping_add(b)
                .rotate_left(a.wrapping_add(b));

            b = key_as_words[key_as_words_index];

            expanded_key_index = (expanded_key_index + 1) % key_table.len();
            key_as_words_index = (key_as_words_index + 1) % key_as_words.len();
        }

        key_table
    }
}

impl<W, R, B> RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArraySize,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    pub(crate) fn words_from_block(block: &Block<W>) -> (W, W) {
        // Block size is 2 * word::BYTES so the unwrap is safe
        let a = W::from_le_bytes(block[..W::Bytes::USIZE].try_into().unwrap());
        let b = W::from_le_bytes(block[W::Bytes::USIZE..].try_into().unwrap());

        (a, b)
    }

    pub(crate) fn block_from_words(a: W, b: W, out_block: &mut Block<W>) {
        let (left, right) = out_block.split_at_mut(W::Bytes::USIZE);

        left.copy_from_slice(&a.to_le_bytes());
        right.copy_from_slice(&b.to_le_bytes());
    }
}

impl<W, R, B> KeyInit for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArraySize,
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
    BlockSize<W>: ArraySize,
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

impl<W, R, B> BlockSizeUser for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArraySize,
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

impl<W, R, B> ParBlocksSizeUser for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArraySize,
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

impl<W, R, B> BlockCipherEncrypt for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArraySize,
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
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl<W, R, B> BlockCipherEncBackend for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArraySize,
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
    fn encrypt_block(&self, mut block: InOut<'_, '_, cipher::Block<Self>>) {
        let (mut a, mut b) = Self::words_from_block(block.get_in());
        let key = &self.key_table;

        a = a.wrapping_add(key[0]);
        b = b.wrapping_add(key[1]);

        for i in 1..=R::USIZE {
            a = a.bitxor(b).rotate_left(b).wrapping_add(key[2 * i]);
            b = b.bitxor(a).rotate_left(a).wrapping_add(key[2 * i + 1]);
        }

        Self::block_from_words(a, b, block.get_out())
    }
}

impl<W, R, B> BlockCipherDecrypt for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArraySize,
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
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl<W, R, B> BlockCipherDecBackend for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArraySize,
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
    fn decrypt_block(&self, mut block: InOut<'_, '_, cipher::Block<Self>>) {
        let (mut a, mut b) = Self::words_from_block(block.get_in());
        let key = &self.key_table;

        for i in (1..=R::USIZE).rev() {
            b = b.wrapping_sub(key[2 * i + 1]).rotate_right(a).bitxor(a);
            a = a.wrapping_sub(key[2 * i]).rotate_right(b).bitxor(b);
        }

        b = b.wrapping_sub(key[1]);
        a = a.wrapping_sub(key[0]);

        Self::block_from_words(a, b, block.get_out())
    }
}

impl<W, R, B> AlgorithmName for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArraySize,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RC5 - {}/{}/{}",
            core::any::type_name::<W>(),
            <R as Unsigned>::to_u8(),
            <R as Unsigned>::to_u8(),
        )
    }
}

impl<W, R, B> fmt::Debug for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArraySize,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RC5 - {}/{}/{} {{ ... }}",
            core::any::type_name::<W>(),
            <R as Unsigned>::to_u8(),
            <R as Unsigned>::to_u8(),
        )
    }
}

#[cfg(feature = "zeroize")]
impl<W, R, B> ZeroizeOnDrop for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArraySize,
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

impl<W, R, B> Drop for RC5<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U2>,
    BlockSize<W>: ArraySize,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U1>,
    Sum<R, U1>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        self.key_table.zeroize()
    }
}
