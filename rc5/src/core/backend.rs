use core::{
    cmp::max,
    marker::PhantomData,
    ops::{Add, Div, Mul, Sub},
};

use cipher::{
    generic_array::{sequence::GenericSequence, ArrayLength, GenericArray},
    inout::InOut,
    typenum::{Diff, IsLess, Le, NonZero, Sum, U1, U2},
    typenum::{Unsigned, U256},
};

use super::{
    Block, BlockSize, ExpandedKeyTable, ExpandedKeyTableSize, Key, KeyAsWords, KeyAsWordsSize, Word,
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

impl<W, R, B> RC5<W, R, B>
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
    pub fn new(key: &Key<B>) -> RC5<W, R, B> {
        Self {
            key_table: Self::substitute_key(key),
            _key_size: PhantomData,
        }
    }

    fn substitute_key(key: &Key<B>) -> ExpandedKeyTable<W, R> {
        let key_as_words = Self::key_into_words(key);
        let expanded_key_table = Self::initialize_expanded_key_table();

        Self::mix_in(expanded_key_table, key_as_words)
    }

    fn key_into_words(key: &Key<B>) -> KeyAsWords<W, B> {
        // can be uninitialized
        let mut key_as_words: GenericArray<W, KeyAsWordsSize<W, B>> = GenericArray::default();

        for i in (0..B::USIZE).rev() {
            key_as_words[i / W::Bytes::USIZE] =
                key_as_words[i / W::Bytes::USIZE].rotate_left(W::EIGHT) + key[i].into();
            // no need for wrapping addition since we are adding a byte sized uint onto an uint with its lsb byte zeroed
        }

        key_as_words
    }

    fn initialize_expanded_key_table() -> ExpandedKeyTable<W, R> {
        // must be zero initialized
        let mut expanded_key_table: GenericArray<W, ExpandedKeyTableSize<R>> =
            GenericArray::generate(|_| W::ZERO);

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
    pub fn encrypt(&self, mut block: InOut<'_, '_, Block<W>>) {
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

    pub fn decrypt(&self, mut block: InOut<'_, '_, Block<W>>) {
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

    fn words_from_block(block: &Block<W>) -> (W, W) {
        // Block size is 2 * word::BYTES so the unwrap is safe
        let a = W::from_le_bytes(block[..W::Bytes::USIZE].try_into().unwrap());
        let b = W::from_le_bytes(block[W::Bytes::USIZE..].try_into().unwrap());

        (a, b)
    }

    fn block_from_words(a: W, b: W, out_block: &mut Block<W>) {
        let (left, right) = out_block.split_at_mut(W::Bytes::USIZE);

        left.copy_from_slice(&a.to_le_bytes());
        right.copy_from_slice(&b.to_le_bytes());
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
