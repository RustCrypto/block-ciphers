#![allow(unsafe_op_in_unsafe_fn)]

use crate::{
    Block, Key,
    consts::{P, P_INV},
    fused_tables::{DEC_TABLE, ENC_TABLE, Table},
    utils::KEYGEN,
};
use cipher::{
    BlockCipherDecBackend, BlockCipherEncBackend, BlockSizeUser, InOut, ParBlocks,
    ParBlocksSizeUser, consts, typenum::Unsigned,
};

use core::arch::aarch64::*;

pub(super) type RoundKeys = [uint8x16_t; 10];

type ParBlocksSize = consts::U8;

#[rustfmt::skip]
macro_rules! unroll_par {
    ($var:ident, $body:block) => {
        { let $var: usize = 0; $body; }
        { let $var: usize = 1; $body; }
        { let $var: usize = 2; $body; }
        { let $var: usize = 3; $body; }
        { let $var: usize = 4; $body; }
        { let $var: usize = 5; $body; }
        { let $var: usize = 6; $body; }
        { let $var: usize = 7; $body; }

    };
}

#[inline(always)]
unsafe fn sub_bytes(block: uint8x16_t, sbox: &[u8; 256]) -> uint8x16_t {
    let value_vector = vdupq_n_u8(64);

    //Split the sbox table into four parts
    let sbox_part1 = uint8x16x4_t(
        vld1q_u8(&sbox[0] as *const u8),
        vld1q_u8(&sbox[16] as *const u8),
        vld1q_u8(&sbox[32] as *const u8),
        vld1q_u8(&sbox[48] as *const u8),
    );

    let sbox_part2 = uint8x16x4_t(
        vld1q_u8(&sbox[64] as *const u8),
        vld1q_u8(&sbox[80] as *const u8),
        vld1q_u8(&sbox[96] as *const u8),
        vld1q_u8(&sbox[112] as *const u8),
    );

    let sbox_part3 = uint8x16x4_t(
        vld1q_u8(&sbox[128] as *const u8),
        vld1q_u8(&sbox[144] as *const u8),
        vld1q_u8(&sbox[160] as *const u8),
        vld1q_u8(&sbox[176] as *const u8),
    );

    let sbox_part4 = uint8x16x4_t(
        vld1q_u8(&sbox[192] as *const u8),
        vld1q_u8(&sbox[208] as *const u8),
        vld1q_u8(&sbox[224] as *const u8),
        vld1q_u8(&sbox[240] as *const u8),
    );

    // Indexing each part of the sbox table
    let result1 = vqtbl4q_u8(sbox_part1, block);
    let block_1 = vsubq_u8(block, value_vector);
    let result2 = vqtbl4q_u8(sbox_part2, block_1);
    let block_2 = vsubq_u8(block_1, value_vector);
    let result3 = vqtbl4q_u8(sbox_part3, block_2);
    let block_3 = vsubq_u8(block_2, value_vector);
    let result4 = vqtbl4q_u8(sbox_part4, block_3);
    // Merging results
    let result = vorrq_u8(vorrq_u8(result1, result2), vorrq_u8(result3, result4));

    result
}

#[inline(always)]
unsafe fn transform(block: uint8x16_t, table: &Table) -> uint8x16_t {
    macro_rules! get {
        ($table:expr, $ind:expr, $i:expr) => {{
            let idx = vgetq_lane_u16($ind, $i) as usize;
            let p = $table.0.as_ptr().add(idx);
            // correct alignment of `p` is guaranteed since offset values
            // are shifted by 4 bits left and the table is aligned to 16 bytes
            debug_assert_eq!(p as usize % 16, 0);
            vld1q_u8(p)
        }};
    }

    macro_rules! xor_get {
        ($val:expr, $table:expr, $ind:expr, $i:expr) => {
            $val = veorq_u8($val, get!($table, $ind, $i));
        };
    }

    let ind = vcombine_u8(
        vcreate_u8(0x0706050403020100),
        vcreate_u8(0x0f0e0d0c0b0a0908),
    );
    let test = vzip1q_u8(block, ind);

    let lind = vshlq_n_u16(vreinterpretq_u16_u8(test), 4);

    let mut lt = get!(table, lind, 0);

    xor_get!(lt, table, lind, 1);
    xor_get!(lt, table, lind, 2);
    xor_get!(lt, table, lind, 3);
    xor_get!(lt, table, lind, 4);
    xor_get!(lt, table, lind, 5);
    xor_get!(lt, table, lind, 6);
    xor_get!(lt, table, lind, 7);

    let rind = vshlq_n_u16(vreinterpretq_u16_u8(vzip2q_u8(block, ind)), 4);

    let mut rt = get!(table, rind, 0);
    xor_get!(rt, table, rind, 1);
    xor_get!(rt, table, rind, 2);
    xor_get!(rt, table, rind, 3);
    xor_get!(rt, table, rind, 4);
    xor_get!(rt, table, rind, 5);
    xor_get!(rt, table, rind, 6);
    xor_get!(rt, table, rind, 7);

    veorq_u8(lt, rt)
}

pub fn expand_enc_keys(key: &Key) -> RoundKeys {
    macro_rules! next_const {
        ($i:expr) => {{
            let p = KEYGEN.as_ptr() as *const uint8x16_t;
            // correct alignment of `p` is guaranteed since the table
            // is aligned to 16 bytes
            let p = p.add($i);
            debug_assert_eq!(p as usize % 16, 0);
            $i += 1;
            vld1q_u8(p as *const u8)
        }};
    }

    unsafe {
        let mut enc_keys = [vdupq_n_u8(0); 10];

        let pk: *const uint8x16_t = key.as_ptr() as *const uint8x16_t;
        let mut k1 = vld1q_u8(pk as *const u8);
        let mut k2 = vld1q_u8(pk.add(1) as *const u8);
        enc_keys[0] = k1;
        enc_keys[1] = k2;

        let mut cidx = 0;
        for i in 1..5 {
            for _ in 0..4 {
                let mut t = veorq_u8(k1, next_const!(cidx));
                t = transform(t, &ENC_TABLE);
                k2 = veorq_u8(k2, t);

                let mut t = veorq_u8(k2, next_const!(cidx));
                t = transform(t, &ENC_TABLE);
                k1 = veorq_u8(k1, t);
            }

            enc_keys[2 * i] = k1;
            enc_keys[2 * i + 1] = k2;
        }

        enc_keys
    }
}

pub fn inv_enc_keys(enc_keys: &RoundKeys) -> RoundKeys {
    unsafe {
        let mut dec_keys = [vdupq_n_u8(0); 10];

        dec_keys[0] = enc_keys[9];
        for i in 1..9 {
            let k = sub_bytes(enc_keys[i], &P);
            dec_keys[9 - i] = transform(k, &DEC_TABLE);
        }
        dec_keys[9] = enc_keys[0];

        dec_keys
    }
}

pub(crate) struct EncBackend<'a>(pub(crate) &'a RoundKeys);

impl BlockSizeUser for EncBackend<'_> {
    type BlockSize = consts::U16;
}

impl ParBlocksSizeUser for EncBackend<'_> {
    type ParBlocksSize = ParBlocksSize;
}

impl BlockCipherEncBackend for EncBackend<'_> {
    #[inline]
    fn encrypt_block(&self, block: InOut<'_, '_, Block>) {
        let k = self.0;
        unsafe {
            let (in_ptr, out_ptr) = block.into_raw();
            let mut b = vld1q_u8(in_ptr as *const u8);

            for i in 0..9 {
                b = veorq_u8(b, k[i]);
                b = transform(b, &ENC_TABLE);
            }
            b = veorq_u8(b, k[9]);
            vst1q_u8(out_ptr as *mut u8, b);
        }
    }

    #[inline]
    fn encrypt_par_blocks(&self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
        let k = self.0;
        unsafe {
            let (in_ptr, out_ptr) = blocks.into_raw();
            let in_ptr = in_ptr as *mut uint8x16_t;
            let out_ptr = out_ptr as *mut uint8x16_t;

            let mut blocks = [vdupq_n_u8(0); ParBlocksSize::USIZE];
            unroll_par! {
                i, {
                    blocks[i] = vld1q_u8(in_ptr.add(i) as *const u8);
                }
            };

            for i in 0..9 {
                unroll_par!(j, {
                    let t = veorq_u8(blocks[j], k[i]);
                    blocks[j] = transform(t, &ENC_TABLE);
                });
            }

            unroll_par! {
                i, {
                    let t = veorq_u8(blocks[i], k[9]);
                    vst1q_u8(out_ptr.add(i) as *mut u8, t);
                }
            };
        }
    }
}

pub(crate) struct DecBackend<'a>(pub(crate) &'a RoundKeys);

impl BlockSizeUser for DecBackend<'_> {
    type BlockSize = consts::U16;
}

impl ParBlocksSizeUser for DecBackend<'_> {
    type ParBlocksSize = ParBlocksSize;
}

impl BlockCipherDecBackend for DecBackend<'_> {
    #[inline]
    fn decrypt_block(&self, block: InOut<'_, '_, Block>) {
        let k = self.0;
        unsafe {
            let (in_ptr, out_ptr) = block.into_raw();
            let mut b = vld1q_u8(in_ptr as *const u8);

            b = veorq_u8(b, k[0]);

            b = sub_bytes(b, &P);
            b = transform(b, &DEC_TABLE);

            for i in 1..9 {
                b = transform(b, &DEC_TABLE);
                b = veorq_u8(b, k[i]);
            }
            b = sub_bytes(b, &P_INV);
            b = veorq_u8(b, k[9]);

            vst1q_u8(out_ptr as *mut u8, b);
        }
    }
    #[inline]
    fn decrypt_par_blocks(&self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
        let k = self.0;
        unsafe {
            let (in_ptr, out_ptr) = blocks.into_raw();
            let in_ptr = in_ptr as *mut uint8x16_t;
            let out_ptr = out_ptr as *mut uint8x16_t;

            let mut blocks = [vdupq_n_u8(0); ParBlocksSize::USIZE];
            unroll_par! {
                i, {
                    blocks[i] = vld1q_u8(in_ptr.add(i) as *const u8);
                }
            };

            unroll_par! {
                i, {
                    let t = veorq_u8(blocks[i], k[0]);
                    let t = sub_bytes(t, &P);
                    blocks[i] = transform(t, &DEC_TABLE);
                }
            }

            for i in 1..9 {
                unroll_par! {
                    j, {
                        let t = transform(blocks[j], &DEC_TABLE);
                        blocks[j] = veorq_u8(t, k[i]);
                    }
                }
            }

            unroll_par! {
                i, {
                    let t = sub_bytes(blocks[i], &P_INV);
                    let t2 = veorq_u8(t, k[9]);
                    vst1q_u8(out_ptr.add(i) as *mut u8, t2);
                }
            }
        }
    }
}
