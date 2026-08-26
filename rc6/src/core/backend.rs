use core::{
    cmp::max,
    marker::PhantomData,
    ops::{Add, Div, Mul, Sub},
};

use cipher::{
    array::{Array, ArraySize},
    inout::InOut,
    typenum::{Diff, IsLess, Le, NonZero, Sum, U1, U2, U4, U256, Unsigned},
};

use super::{
    Block, BlockSize, ExpandedKeyTable, ExpandedKeyTableSize, Key, KeyAsWords, KeyAsWordsSize, Word,
};

pub struct RC6<W, R, B>
where
    W: Word,
    R: Unsigned,
    R: IsLess<U256>,
    // ExpandedKeyTableSize
    R: Add<U2>,
    Sum<R, U2>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    key_table: ExpandedKeyTable<W, R>,
    _key_size: PhantomData<B>,
}

impl<W, R, B> RC6<W, R, B>
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
    pub fn new(key: &Key<B>) -> RC6<W, R, B> {
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

impl<W, R, B> RC6<W, R, B>
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
    pub fn encrypt(&self, mut block: InOut<'_, '_, Block<W>>) {
        let (mut a, mut b, mut c, mut d) = Self::words_from_block(block.get_in());
        let key = &self.key_table;
        let log_w = W::from((usize::BITS - 1 - (W::Bytes::USIZE * 8).leading_zeros()) as u8);

        b = b.wrapping_add(key[0]);
        d = d.wrapping_add(key[1]);

        for i in 1..=R::USIZE {
            let t = b
                .wrapping_mul(b.wrapping_mul(W::from(2)).wrapping_add(W::from(1)))
                .rotate_left(log_w);
            let u = d
                .wrapping_mul(d.wrapping_mul(W::from(2)).wrapping_add(W::from(1)))
                .rotate_left(log_w);
            a = a.bitxor(t).rotate_left(u).wrapping_add(key[2 * i]);
            c = c.bitxor(u).rotate_left(t).wrapping_add(key[2 * i + 1]);
            let tmp = a;
            a = b;
            b = c;
            c = d;
            d = tmp;
        }

        a = a.wrapping_add(key[2 * R::USIZE + 2]);
        c = c.wrapping_add(key[2 * R::USIZE + 3]);

        Self::block_from_words(a, b, c, d, block.get_out())
    }

    pub fn decrypt(&self, mut block: InOut<'_, '_, Block<W>>) {
        let (mut a, mut b, mut c, mut d) = Self::words_from_block(block.get_in());
        let key = &self.key_table;
        let log_w = W::from((usize::BITS - 1 - (W::Bytes::USIZE * 8).leading_zeros()) as u8);

        c = c.wrapping_sub(key[2 * R::USIZE + 3]);
        a = a.wrapping_sub(key[2 * R::USIZE + 2]);

        for i in (1..=R::USIZE).rev() {
            let tmp = d;
            d = c;
            c = b;
            b = a;
            a = tmp;
            let u = d
                .wrapping_mul(d.wrapping_mul(W::from(2)).wrapping_add(W::from(1)))
                .rotate_left(log_w);
            let t = b
                .wrapping_mul(b.wrapping_mul(W::from(2)).wrapping_add(W::from(1)))
                .rotate_left(log_w);
            c = c.wrapping_sub(key[2 * i + 1]).rotate_right(t).bitxor(u);
            a = a.wrapping_sub(key[2 * i]).rotate_right(u).bitxor(t);
        }

        d = d.wrapping_sub(key[1]);
        b = b.wrapping_sub(key[0]);

        Self::block_from_words(a, b, c, d, block.get_out())
    }

    fn words_from_block(block: &Block<W>) -> (W, W, W, W) {
        // Block size is 4 * word::BYTES so the unwrap is safe
        let a = W::from_le_bytes(block[..W::Bytes::USIZE].try_into().unwrap());
        let b = W::from_le_bytes(
            block[W::Bytes::USIZE..W::Bytes::USIZE * 2]
                .try_into()
                .unwrap(),
        );
        let c = W::from_le_bytes(
            block[W::Bytes::USIZE * 2..W::Bytes::USIZE * 3]
                .try_into()
                .unwrap(),
        );
        let d = W::from_le_bytes(
            block[W::Bytes::USIZE * 3..W::Bytes::USIZE * 4]
                .try_into()
                .unwrap(),
        );

        (a, b, c, d)
    }

    fn block_from_words(a: W, b: W, c: W, d: W, out_block: &mut Block<W>) {
        let (left, right) = out_block.split_at_mut(W::Bytes::USIZE * 2);
        let (l_l, l_h) = left.split_at_mut(W::Bytes::USIZE);
        let (r_l, r_h) = right.split_at_mut(W::Bytes::USIZE);

        l_l.copy_from_slice(&a.to_le_bytes());
        l_h.copy_from_slice(&b.to_le_bytes());
        r_l.copy_from_slice(&c.to_le_bytes());
        r_h.copy_from_slice(&d.to_le_bytes());
    }
}
