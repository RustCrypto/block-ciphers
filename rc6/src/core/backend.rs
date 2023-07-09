use core::{
    cmp::max,
    marker::PhantomData,
    ops::{Add, Div, Mul, Sub},
};

use cipher::{
    generic_array::{sequence::GenericSequence, ArrayLength, GenericArray},
    inout::InOut,
    typenum::{Diff, IsLess, Le, NonZero, Sum, Unsigned, U1, U2, U256, U4},
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
    ExpandedKeyTableSize<R>: ArrayLength<W>,
{
    key_table: ExpandedKeyTable<W, R>,
    _key_size: PhantomData<B>,
}

impl<W, R, B> RC6<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U4>,
    BlockSize<W>: ArrayLength<u8>,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U2>,
    Sum<R, U2>: Mul<U2>,
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

impl<W, R, B> RC6<W, R, B>
where
    W: Word,
    // Block size
    W::Bytes: Mul<U4>,
    BlockSize<W>: ArrayLength<u8>,
    // Rounds range
    R: Unsigned,
    R: IsLess<U256>,
    Le<R, U256>: NonZero,
    // ExpandedKeyTableSize
    R: Add<U2>,
    Sum<R, U2>: Mul<U2>,
    ExpandedKeyTableSize<R>: ArrayLength<W>,
{
    pub fn encrypt(&self, mut block: InOut<'_, '_, Block<W>>) {
        let (mut a, mut b, mut c, mut d) = Self::words_from_block(block.get_in());
        let key = &self.key_table;
        let log_w = W::from((W::Bytes::USIZE as f64 * 8 as f64).log2() as u8);

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
            let (tmp_a, tmp_b, tmp_c, tmp_d) = (b, c, d, a);
            a = tmp_a;
            b = tmp_b;
            c = tmp_c;
            d = tmp_d;
        }

        a = a.wrapping_add(key[2 * R::USIZE + 2]);
        c = c.wrapping_add(key[2 * R::USIZE + 3]);

        Self::block_from_words(a, b, c, d, block.get_out())
    }

    pub fn decrypt(&self, mut block: InOut<'_, '_, Block<W>>) {
        let (mut a, mut b, mut c, mut d) = Self::words_from_block(block.get_in());
        let key = &self.key_table;
        let log_w = W::from((W::Bytes::USIZE as f64 * 8 as f64).log2() as u8);

        c = c.wrapping_sub(key[2 * R::USIZE + 3]);
        a = a.wrapping_sub(key[2 * R::USIZE + 2]);

        for i in (1..=R::USIZE).rev() {
            let (tmp_a, tmp_b, tmp_c, tmp_d) = (d, a, b, c);
            a = tmp_a;
            b = tmp_b;
            c = tmp_c;
            d = tmp_d;
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

#[cfg(test)]
mod tests {
    use crate::block_cipher::{RC6_16_16_8, RC6_32_20_16, RC6_64_24_24, RC6_8_12_4};
    use crate::core::backend::GenericArray;
    use rand::{thread_rng, Rng};

    #[macro_export]
    macro_rules! words_block_conv {
        ($rc_tyoe:ident, $key_size:expr) => {
            let mut pt = [0u8; $key_size];
            thread_rng().fill(&mut pt[..]);
            let block = GenericArray::clone_from_slice(&pt);
            let mut after_block = block.clone();
            let (a, b, c, d) = $rc_tyoe::words_from_block(&block);
            $rc_tyoe::block_from_words(a, b, c, d, &mut after_block);
            assert_eq!(block, after_block);
        };
    }

    #[test]
    fn words_block_test() {
        words_block_conv!(RC6_16_16_8, 8);
        words_block_conv!(RC6_32_20_16, 16);
        words_block_conv!(RC6_64_24_24, 32);
        words_block_conv!(RC6_8_12_4, 4);
    }
}
