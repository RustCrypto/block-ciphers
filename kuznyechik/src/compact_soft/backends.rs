use crate::{
    Block, Key,
    consts::{P, P_INV},
    utils::{KEYGEN, l_step},
};
use cipher::{
    BlockCipherDecBackend, BlockCipherEncBackend, BlockSizeUser, InOut, ParBlocksSizeUser, consts,
};

pub(super) type RoundKeys = [Block; 10];

#[inline(always)]
fn x(a: &mut Block, b: &Block) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

#[inline(always)]
fn lsx(block: &mut Block, key: &Block) {
    x(block, key);
    // s
    for i in 0..16 {
        block[i] = P[block[i] as usize];
    }
    // l
    for i in 0..16 {
        block.0 = l_step(block.0, i);
    }
}

#[inline(always)]
fn lsx_inv(block: &mut Block, key: &Block) {
    x(block, key);
    // l_inv
    for i in 0..16 {
        block.0 = l_step(block.0, 15 - i);
    }
    // s_inv
    for i in 0..16 {
        block[15 - i] = P_INV[block[15 - i] as usize];
    }
}

fn get_c(n: usize) -> Block {
    KEYGEN[n].0.into()
}

fn f(k1: &mut Block, k2: &mut Block, n: usize) {
    for i in 0..4 {
        let mut k1_cpy = *k1;
        lsx(&mut k1_cpy, &get_c(8 * n + 2 * i));
        x(k2, &k1_cpy);

        let mut k2_cpy = *k2;
        lsx(&mut k2_cpy, &get_c(8 * n + 2 * i + 1));
        x(k1, &k2_cpy);
    }
}

pub(super) fn expand(key: &Key) -> RoundKeys {
    let mut keys = RoundKeys::default();

    let mut k1 = Block::default();
    let mut k2 = Block::default();

    k1.copy_from_slice(&key[..16]);
    k2.copy_from_slice(&key[16..]);

    keys[0] = k1;
    keys[1] = k2;

    for i in 1..5 {
        f(&mut k1, &mut k2, i - 1);
        keys[2 * i] = k1;
        keys[2 * i + 1] = k2;
    }
    keys
}

pub(crate) struct EncBackend<'a>(pub(crate) &'a RoundKeys);

impl BlockSizeUser for EncBackend<'_> {
    type BlockSize = consts::U16;
}

impl ParBlocksSizeUser for EncBackend<'_> {
    type ParBlocksSize = consts::U1;
}

impl BlockCipherEncBackend for EncBackend<'_> {
    #[inline]
    fn encrypt_block(&self, mut block: InOut<'_, '_, Block>) {
        let mut b = *block.get_in();
        for i in 0..9 {
            lsx(&mut b, &self.0[i]);
        }
        x(&mut b, &self.0[9]);
        *block.get_out() = b;
    }
}

pub(crate) struct DecBackend<'a>(pub(crate) &'a RoundKeys);

impl BlockSizeUser for DecBackend<'_> {
    type BlockSize = consts::U16;
}

impl ParBlocksSizeUser for DecBackend<'_> {
    type ParBlocksSize = consts::U1;
}

impl BlockCipherDecBackend for DecBackend<'_> {
    #[inline]
    fn decrypt_block(&self, mut block: InOut<'_, '_, Block>) {
        let mut b = *block.get_in();
        for i in 0..9 {
            lsx_inv(&mut b, &self.0[9 - i]);
        }
        x(&mut b, &self.0[0]);
        *block.get_out() = b;
    }
}
