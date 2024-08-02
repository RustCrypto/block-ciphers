use super::consts::{Table, DEC_TABLE, ENC_TABLE, RKEY_GEN};
use crate::{
    consts::{P, P_INV},
    Block, Key,
};
use cipher::{
    array::Array, consts, inout::InOut, BlockBackend, BlockSizeUser, ParBlocks, ParBlocksSizeUser,
};

pub(super) type RoundKeys = [u128; 10];
type ParBlocksSize = consts::U3;

#[rustfmt::skip]
macro_rules! unroll_par {
    ($var:ident, $body:block) => {
        { let $var: usize = 0; $body; }
        { let $var: usize = 1; $body; }
        { let $var: usize = 2; $body; }
    };
}

#[inline(always)]
fn sub_bytes(block: u128, sbox: &[u8; 256]) -> u128 {
    u128::from_le_bytes(block.to_le_bytes().map(|v| sbox[v as usize]))
}

#[inline(always)]
fn transform(block: u128, table: &Table) -> u128 {
    let table: &[[u128; 256]; 16] = unsafe { &*(table.as_ptr().cast()) };
    let block = block.to_le_bytes();
    let mut res = 0u128;
    for i in 0..16 {
        res ^= table[i][block[i] as usize];
    }
    #[cfg(target_endian = "big")]
    let res = res.swap_bytes();
    res
}

pub(super) fn expand_enc_keys(key: &Key) -> RoundKeys {
    #[inline(always)]
    fn next_const(i: usize) -> u128 {
        // correct alignment of `p` is guaranteed since the table is aligned to 16 bytes
        let t: &[u128; 32] = unsafe { &*(RKEY_GEN.as_ptr().cast()) };
        let val = t[i];
        #[cfg(target_endian = "big")]
        let val = val.swap_bytes();
        val
    }

    let mut enc_keys = [0; 10];

    let mut k1 = u128::from_le_bytes(key[..16].try_into().unwrap());
    let mut k2 = u128::from_le_bytes(key[16..].try_into().unwrap());

    enc_keys[0] = k1;
    enc_keys[1] = k2;

    let mut cidx = 0;
    for i in 1..5 {
        for _ in 0..4 {
            let mut t = k1 ^ next_const(cidx);
            cidx += 1;
            t = transform(t, &ENC_TABLE);
            k2 ^= t;

            let mut t = k2 ^ next_const(cidx);
            cidx += 1;
            t = transform(t, &ENC_TABLE);
            k1 ^= t;
        }

        enc_keys[2 * i] = k1;
        enc_keys[2 * i + 1] = k2;
    }

    enc_keys
}

pub(super) fn inv_enc_keys(enc_keys: &RoundKeys) -> RoundKeys {
    let mut dec_keys = [0; 10];

    dec_keys[0] = enc_keys[9];
    for i in 1..9 {
        let k = sub_bytes(enc_keys[i], &P);
        dec_keys[9 - i] = transform(k, &DEC_TABLE);
    }
    dec_keys[9] = enc_keys[0];

    dec_keys
}

pub(crate) struct EncBackend<'a>(pub(crate) &'a RoundKeys);

impl<'a> BlockSizeUser for EncBackend<'a> {
    type BlockSize = consts::U16;
}

impl<'a> ParBlocksSizeUser for EncBackend<'a> {
    type ParBlocksSize = ParBlocksSize;
}

impl<'a> BlockBackend for EncBackend<'a> {
    #[inline]
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block>) {
        let k = self.0;

        let mut b: u128 = u128::from_le_bytes(block.get_in().0);

        for i in 0..9 {
            b ^= k[i];
            b = transform(b, &ENC_TABLE);
        }
        b ^= k[9];

        *block.get_out() = Array(b.to_le_bytes());
    }

    #[inline]
    fn proc_par_blocks(&mut self, mut blocks: InOut<'_, '_, ParBlocks<Self>>) {
        let k = self.0;

        let mut bs = blocks.get_in().0.map(|b| u128::from_le_bytes(b.0));

        for i in 0..9 {
            unroll_par!(j, {
                bs[j] ^= k[i];
                bs[j] = transform(bs[j], &ENC_TABLE);
            });
        }

        let blocks_out = blocks.get_out();
        unroll_par!(i, {
            bs[i] ^= k[9];
            blocks_out[i].0 = u128::to_le_bytes(bs[i]);
        });
    }
}

pub(crate) struct DecBackend<'a>(pub(crate) &'a RoundKeys);

impl<'a> BlockSizeUser for DecBackend<'a> {
    type BlockSize = consts::U16;
}

impl<'a> ParBlocksSizeUser for DecBackend<'a> {
    type ParBlocksSize = consts::U1;
}

impl<'a> BlockBackend for DecBackend<'a> {
    #[inline]
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block>) {
        let k = self.0;

        let mut b: u128 = u128::from_le_bytes(block.get_in().0);

        b ^= k[0];
        b = sub_bytes(b, &P);
        b = transform(b, &DEC_TABLE);

        for i in 1..9 {
            b = transform(b, &DEC_TABLE);
            b ^= k[i];
        }
        b = sub_bytes(b, &P_INV);
        b ^= k[9];

        *block.get_out() = Array(b.to_le_bytes());
    }
}
