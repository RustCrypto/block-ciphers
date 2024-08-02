use super::consts::GF;
use crate::consts::{P, P_INV};
use crate::{Block, Key};
use cipher::{
    consts::{U1, U16},
    inout::InOut,
    BlockBackend, BlockSizeUser, ParBlocks, ParBlocksSizeUser,
};

pub(super) type RoundKeys = [Block; 10];

#[inline(always)]
fn x(a: &mut Block, b: &Block) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

fn l_step(msg: &mut Block, i: usize) {
    #[inline(always)]
    fn get_idx(b: usize, i: usize) -> usize {
        b.wrapping_sub(i) & 0x0F
    }
    #[inline(always)]
    fn get_m(msg: &Block, b: usize, i: usize) -> usize {
        msg[get_idx(b, i)] as usize
    }

    let mut x = msg[get_idx(15, i)];
    x ^= GF[3][get_m(msg, 14, i)];
    x ^= GF[1][get_m(msg, 13, i)];
    x ^= GF[2][get_m(msg, 12, i)];
    x ^= GF[0][get_m(msg, 11, i)];
    x ^= GF[5][get_m(msg, 10, i)];
    x ^= GF[4][get_m(msg, 9, i)];
    x ^= msg[get_idx(8, i)];
    x ^= GF[6][get_m(msg, 7, i)];
    x ^= msg[get_idx(6, i)];
    x ^= GF[4][get_m(msg, 5, i)];
    x ^= GF[5][get_m(msg, 4, i)];
    x ^= GF[0][get_m(msg, 3, i)];
    x ^= GF[2][get_m(msg, 2, i)];
    x ^= GF[1][get_m(msg, 1, i)];
    x ^= GF[3][get_m(msg, 0, i)];
    msg[get_idx(15, i)] = x;
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
        l_step(block, i);
    }
}

#[inline(always)]
fn lsx_inv(block: &mut Block, key: &Block) {
    x(block, key);
    // l_inv
    for i in 0..16 {
        l_step(block, 15 - i);
    }
    // s_inv
    for i in 0..16 {
        block[15 - i] = P_INV[block[15 - i] as usize];
    }
}

fn get_c(n: usize) -> Block {
    let mut v = Block::default();
    v[15] = n as u8;
    for i in 0..16 {
        l_step(&mut v, i);
    }
    v
}

fn f(k1: &mut Block, k2: &mut Block, n: usize) {
    for i in 0..4 {
        let mut k1_cpy = *k1;
        lsx(&mut k1_cpy, &get_c(8 * n + 2 * i + 1));
        x(k2, &k1_cpy);

        let mut k2_cpy = *k2;
        lsx(&mut k2_cpy, &get_c(8 * n + 2 * i + 2));
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

impl<'a> BlockSizeUser for EncBackend<'a> {
    type BlockSize = U16;
}

impl<'a> ParBlocksSizeUser for EncBackend<'a> {
    type ParBlocksSize = U1;
}

impl<'a> BlockBackend for EncBackend<'a> {
    #[inline]
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block>) {
        let mut b = *block.get_in();
        for i in 0..9 {
            lsx(&mut b, &self.0[i]);
        }
        x(&mut b, &self.0[9]);
        *block.get_out() = b;
    }

    #[inline(always)]
    fn proc_par_blocks(&mut self, mut blocks: InOut<'_, '_, ParBlocks<Self>>) {
        self.proc_block(blocks.get(0));
    }
}

pub(crate) struct DecBackend<'a>(pub(crate) &'a RoundKeys);

impl<'a> BlockSizeUser for DecBackend<'a> {
    type BlockSize = U16;
}

impl<'a> ParBlocksSizeUser for DecBackend<'a> {
    type ParBlocksSize = U1;
}

impl<'a> BlockBackend for DecBackend<'a> {
    #[inline]
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block>) {
        let mut b = *block.get_in();
        for i in 0..9 {
            lsx_inv(&mut b, &self.0[9 - i]);
        }
        x(&mut b, &self.0[0]);
        *block.get_out() = b;
    }

    #[inline(always)]
    fn proc_par_blocks(&mut self, mut blocks: InOut<'_, '_, ParBlocks<Self>>) {
        self.proc_block(blocks.get(0));
    }
}
