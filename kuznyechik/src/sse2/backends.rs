#![allow(unsafe_op_in_unsafe_fn)]

use crate::{
    Block, Key,
    consts::{P, P_INV},
    fused_tables::{DEC_TABLE, ENC_TABLE, Table},
    utils::KEYGEN,
};
use cipher::{
    BlockCipherDecBackend, BlockCipherEncBackend, BlockSizeUser, ParBlocks, ParBlocksSizeUser,
    consts::{U4, U16},
    inout::InOut,
    typenum::Unsigned,
};

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

pub(super) type RoundKeys = [__m128i; 10];

type ParBlocksSize = U4;

#[rustfmt::skip]
macro_rules! unroll_par {
    ($var:ident, $body:block) => {
        { let $var: usize = 0; $body; }
        { let $var: usize = 1; $body; }
        { let $var: usize = 2; $body; }
        { let $var: usize = 3; $body; }
    };
}

#[inline(always)]
unsafe fn sub_bytes(block: __m128i, sbox: &[u8; 256]) -> __m128i {
    let t0 = _mm_extract_epi16(block, 0) as u16;
    let t1 = _mm_extract_epi16(block, 1) as u16;
    let t2 = _mm_extract_epi16(block, 2) as u16;
    let t3 = _mm_extract_epi16(block, 3) as u16;
    let t4 = _mm_extract_epi16(block, 4) as u16;
    let t5 = _mm_extract_epi16(block, 5) as u16;
    let t6 = _mm_extract_epi16(block, 6) as u16;
    let t7 = _mm_extract_epi16(block, 7) as u16;

    _mm_set_epi8(
        sbox[(t7 >> 8) as usize] as i8,
        sbox[(t7 & 0xFF) as usize] as i8,
        sbox[(t6 >> 8) as usize] as i8,
        sbox[(t6 & 0xFF) as usize] as i8,
        sbox[(t5 >> 8) as usize] as i8,
        sbox[(t5 & 0xFF) as usize] as i8,
        sbox[(t4 >> 8) as usize] as i8,
        sbox[(t4 & 0xFF) as usize] as i8,
        sbox[(t3 >> 8) as usize] as i8,
        sbox[(t3 & 0xFF) as usize] as i8,
        sbox[(t2 >> 8) as usize] as i8,
        sbox[(t2 & 0xFF) as usize] as i8,
        sbox[(t1 >> 8) as usize] as i8,
        sbox[(t1 & 0xFF) as usize] as i8,
        sbox[(t0 >> 8) as usize] as i8,
        sbox[(t0 & 0xFF) as usize] as i8,
    )
}

#[inline(always)]
unsafe fn transform(block: __m128i, table: &Table) -> __m128i {
    macro_rules! get {
        ($table:expr, $ind:expr, $i:expr) => {{
            let idx = _mm_extract_epi16($ind, $i) as u16 as usize;
            let p = $table.0.as_ptr().add(idx).cast();
            // correct alignment of `p` is guaranteed since offset values
            // are shifted by 4 bits left and the table is aligned to 16 bytes
            debug_assert_eq!(p as usize % 16, 0);
            _mm_load_si128(p)
        }};
    }

    macro_rules! xor_get {
        ($val:expr, $table:expr, $ind:expr, $i:expr) => {
            $val = _mm_xor_si128($val, get!($table, $ind, $i));
        };
    }

    let ind = _mm_set_epi64x(0x0f0e0d0c0b0a0908, 0x0706050403020100);

    let lind = _mm_slli_epi16(_mm_unpacklo_epi8(block, ind), 4);

    let mut lt = get!(table, lind, 0);
    xor_get!(lt, table, lind, 1);
    xor_get!(lt, table, lind, 2);
    xor_get!(lt, table, lind, 3);
    xor_get!(lt, table, lind, 4);
    xor_get!(lt, table, lind, 5);
    xor_get!(lt, table, lind, 6);
    xor_get!(lt, table, lind, 7);

    let rind = _mm_slli_epi16(_mm_unpackhi_epi8(block, ind), 4);

    let mut rt = get!(table, rind, 0);
    xor_get!(rt, table, rind, 1);
    xor_get!(rt, table, rind, 2);
    xor_get!(rt, table, rind, 3);
    xor_get!(rt, table, rind, 4);
    xor_get!(rt, table, rind, 5);
    xor_get!(rt, table, rind, 6);
    xor_get!(rt, table, rind, 7);

    _mm_xor_si128(lt, rt)
}

pub(super) fn expand_enc_keys(key: &Key) -> RoundKeys {
    macro_rules! next_const {
        ($i:expr) => {{
            let p = KEYGEN.as_ptr() as *const __m128i;
            // correct alignment of `p` is guaranteed since the table
            // is aligned to 16 bytes
            let p = p.add($i);
            debug_assert_eq!(p as usize % 16, 0);
            $i += 1;
            _mm_load_si128(p)
        }};
    }

    unsafe {
        let mut enc_keys = [_mm_setzero_si128(); 10];

        let pk: *const __m128i = key.as_ptr() as *const __m128i;
        let mut k1 = _mm_loadu_si128(pk);
        let mut k2 = _mm_loadu_si128(pk.add(1));
        enc_keys[0] = k1;
        enc_keys[1] = k2;

        let mut cidx = 0;
        for i in 1..5 {
            for _ in 0..4 {
                let mut t = _mm_xor_si128(k1, next_const!(cidx));
                t = transform(t, &ENC_TABLE);
                k2 = _mm_xor_si128(k2, t);

                let mut t = _mm_xor_si128(k2, next_const!(cidx));
                t = transform(t, &ENC_TABLE);
                k1 = _mm_xor_si128(k1, t);
            }

            enc_keys[2 * i] = k1;
            enc_keys[2 * i + 1] = k2;
        }

        enc_keys
    }
}

pub(super) fn inv_enc_keys(enc_keys: &RoundKeys) -> RoundKeys {
    unsafe {
        let mut dec_keys = [_mm_setzero_si128(); 10];

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
    type BlockSize = U16;
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
            let mut b = _mm_loadu_si128(in_ptr as *const __m128i);

            for i in 0..9 {
                b = _mm_xor_si128(b, k[i]);
                b = transform(b, &ENC_TABLE);
            }
            b = _mm_xor_si128(b, k[9]);
            _mm_storeu_si128(out_ptr as *mut __m128i, b);
        }
    }

    #[inline]
    fn encrypt_par_blocks(&self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
        let k = self.0;
        unsafe {
            let (in_ptr, out_ptr) = blocks.into_raw();
            let in_ptr = in_ptr as *mut __m128i;
            let out_ptr = out_ptr as *mut __m128i;

            let mut blocks = [_mm_setzero_si128(); ParBlocksSize::USIZE];
            unroll_par! {
                i, {
                    blocks[i] = _mm_loadu_si128(in_ptr.add(i));
                }
            };

            for i in 0..9 {
                unroll_par!(j, {
                    let t = _mm_xor_si128(blocks[j], k[i]);
                    blocks[j] = transform(t, &ENC_TABLE);
                });
            }

            unroll_par! {
                i, {
                    let t = _mm_xor_si128(blocks[i], k[9]);
                    _mm_storeu_si128(out_ptr.add(i), t);
                }
            };
        }
    }
}

pub(crate) struct DecBackend<'a>(pub(crate) &'a RoundKeys);

impl BlockSizeUser for DecBackend<'_> {
    type BlockSize = U16;
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
            let mut b = _mm_loadu_si128(in_ptr as *const __m128i);

            b = _mm_xor_si128(b, k[0]);

            b = sub_bytes(b, &P);
            b = transform(b, &DEC_TABLE);

            for i in 1..9 {
                b = transform(b, &DEC_TABLE);
                b = _mm_xor_si128(b, k[i]);
            }
            b = sub_bytes(b, &P_INV);
            b = _mm_xor_si128(b, k[9]);

            _mm_storeu_si128(out_ptr as *mut __m128i, b)
        }
    }

    #[inline]
    fn decrypt_par_blocks(&self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
        let k = self.0;
        unsafe {
            let (in_ptr, out_ptr) = blocks.into_raw();
            let in_ptr = in_ptr as *mut __m128i;
            let out_ptr = out_ptr as *mut __m128i;

            let mut blocks = [_mm_setzero_si128(); ParBlocksSize::USIZE];
            unroll_par! {
                i, {
                    blocks[i] = _mm_loadu_si128(in_ptr.add(i));
                }
            };

            unroll_par! {
                i, {
                    let t = _mm_xor_si128(blocks[i], k[0]);
                    let t = sub_bytes(t, &P);
                    blocks[i] = transform(t, &DEC_TABLE);
                }
            }

            for i in 1..9 {
                unroll_par! {
                    j, {
                        let t = transform(blocks[j], &DEC_TABLE);
                        blocks[j] = _mm_xor_si128(t, k[i]);
                    }
                }
            }

            unroll_par! {
                i, {
                    let t = sub_bytes(blocks[i], &P_INV);
                    let t2 = _mm_xor_si128(t, k[9]);
                    _mm_storeu_si128(out_ptr.add(i), t2)
                }
            }
        }
    }
}
