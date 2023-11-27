use super::consts::{Table, DEC_TABLE, ENC_TABLE, RKEY_GEN};
use crate::{
    consts::{P, P_INV},
    Block, Key,
};
use cipher::{
    consts, inout::InOut, typenum::Unsigned, BlockBackend, BlockSizeUser, ParBlocks,
    ParBlocksSizeUser,
};
use core::{arch::x86_64::*, mem};

pub(super) type RoundKeys = [__m128i; 10];

type ParBlocksSize = consts::U4;

#[rustfmt::skip]
macro_rules! unroll_par {
    ($var:ident, $body:block) => {
        { let $var: usize = 0; $body; }
        { let $var: usize = 1; $body; }
        // { let $var: usize = 2; $body; }
        // { let $var: usize = 3; $body; }
        // { let $var: usize = 4; $body; }
        // { let $var: usize = 5; $body; }
        // { let $var: usize = 6; $body; }
        // { let $var: usize = 7; $body; }
    };
}

#[inline(always)]
fn sub_bytes128(block: __m128i, sbox: &[u8; 256]) -> __m128i {
    let mut buf: [u8; 16] = unsafe { mem::transmute(block) };
    for i in 0..16 {
        buf[i] = sbox[buf[i] as usize];
    }
    unsafe { mem::transmute_copy(&buf) }
}

#[inline(always)]
fn sub_bytes256(block: __m256i, sbox: &[u8; 256]) -> __m256i {
    let mut buf: [u8; 32] = unsafe { mem::transmute(block) };
    for i in 0..32 {
        buf[i] = sbox[buf[i] as usize];
    }
    unsafe { mem::transmute_copy(&buf) }
}

#[inline(always)]
unsafe fn transform(block: __m128i, table: &Table) -> __m128i {
    macro_rules! get {
        ($table:expr, $ind:expr, $i:expr) => {{
            let idx = _mm_extract_epi16($ind, $i) as u16 as usize;
            let p = &($table.0[idx]) as *const u8 as *const __m128i;
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

#[inline(always)]
unsafe fn transform2(block: __m256i, table: &Table) -> __m256i {
    macro_rules! get {
        ($table:expr, $ind:expr, $i:expr) => {{
            let idx1 = _mm256_extract_epi16($ind, $i) as u16 as usize;
            let idx2 = _mm256_extract_epi16($ind, $i + 8) as u16 as usize;

            let p1 = &($table.0[idx1]) as *const u8 as *const __m128i;
            let p2 = &($table.0[idx2]) as *const u8 as *const __m128i;

            let r1 = _mm_load_si128(p1);
            let r2 = _mm_load_si128(p2);
            _mm256_inserti128_si256(_mm256_castsi128_si256(r1), r2, 1)
        }};
    }

    macro_rules! xor_get {
        ($val:expr, $table:expr, $ind:expr, $i:expr) => {
            $val = _mm256_xor_si256($val, get!($table, $ind, $i));
        };
    }

    let ind = _mm256_set_epi64x(
        0x0f0e0d0c0b0a0908,
        0x0706050403020100,
        0x0f0e0d0c0b0a0908,
        0x0706050403020100,
    );

    let lind = _mm256_slli_epi16(_mm256_unpacklo_epi8(block, ind), 4);

    let mut lt = get!(table, lind, 0);
    xor_get!(lt, table, lind, 1);
    xor_get!(lt, table, lind, 2);
    xor_get!(lt, table, lind, 3);
    xor_get!(lt, table, lind, 4);
    xor_get!(lt, table, lind, 5);
    xor_get!(lt, table, lind, 6);
    xor_get!(lt, table, lind, 7);

    let rind = _mm256_slli_epi16(_mm256_unpackhi_epi8(block, ind), 4);

    let mut rt = get!(table, rind, 0);
    xor_get!(rt, table, rind, 1);
    xor_get!(rt, table, rind, 2);
    xor_get!(rt, table, rind, 3);
    xor_get!(rt, table, rind, 4);
    xor_get!(rt, table, rind, 5);
    xor_get!(rt, table, rind, 6);
    xor_get!(rt, table, rind, 7);

    _mm256_xor_si256(lt, rt)
}

pub(super) fn expand_enc_keys(key: &Key) -> RoundKeys {
    macro_rules! next_const {
        ($i:expr) => {{
            let p = RKEY_GEN.0.as_ptr() as *const __m128i;
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
            let k = sub_bytes128(enc_keys[i], &P);
            dec_keys[9 - i] = transform(k, &DEC_TABLE);
        }
        dec_keys[9] = enc_keys[0];

        dec_keys
    }
}

#[target_feature(enable = "avx2")]
unsafe fn encrypt_par_blocks(in_ptr: *const u8, out_ptr: *mut u8, keys: &RoundKeys) {
    let in_ptr = in_ptr as *mut __m256i;
    let out_ptr = out_ptr as *mut __m256i;

    // One YMM register keeps two blocks
    let mut blocks = [_mm256_setzero_si256(); ParBlocksSize::USIZE / 2];
    unroll_par! {
        i, {
            blocks[i] = _mm256_loadu_si256(in_ptr.add(i));
        }
    };

    for i in 0..9 {
        let rk = _mm256_broadcastsi128_si256(keys[i]);
        unroll_par!(j, {
            let t = _mm256_xor_si256(blocks[j], rk);
            blocks[j] = transform2(t, &ENC_TABLE);
        });
    }

    let rk = _mm256_broadcastsi128_si256(keys[9]);
    unroll_par! {
        i, {
            let t = _mm256_xor_si256(blocks[i], rk);
            _mm256_storeu_si256(out_ptr.add(i), t);
        }
    };
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
    fn proc_block(&mut self, block: InOut<'_, '_, Block>) {
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
    fn proc_par_blocks(&mut self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
        unsafe {
            let (in_ptr, out_ptr) = blocks.into_raw();
            encrypt_par_blocks(in_ptr as *const u8, out_ptr as *mut u8, self.0);
        }
    }
}

pub(crate) struct DecBackend<'a>(pub(crate) &'a RoundKeys);

impl<'a> BlockSizeUser for DecBackend<'a> {
    type BlockSize = consts::U16;
}

impl<'a> ParBlocksSizeUser for DecBackend<'a> {
    type ParBlocksSize = ParBlocksSize;
}

impl<'a> BlockBackend for DecBackend<'a> {
    #[inline]
    fn proc_block(&mut self, block: InOut<'_, '_, Block>) {
        let k = self.0;
        unsafe {
            let (in_ptr, out_ptr) = block.into_raw();
            let mut b = _mm_loadu_si128(in_ptr as *const __m128i);

            b = _mm_xor_si128(b, k[0]);

            b = sub_bytes128(b, &P);
            b = transform(b, &DEC_TABLE);

            for i in 1..9 {
                b = transform(b, &DEC_TABLE);
                b = _mm_xor_si128(b, k[i]);
            }
            b = sub_bytes128(b, &P_INV);
            b = _mm_xor_si128(b, k[9]);

            _mm_storeu_si128(out_ptr as *mut __m128i, b)
        }
    }

    #[inline]
    fn proc_par_blocks(&mut self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
        let k = self.0;
        unsafe {
            let (in_ptr, out_ptr) = blocks.into_raw();
            let in_ptr = in_ptr as *mut __m256i;
            let out_ptr = out_ptr as *mut __m256i;

            let mut blocks = [_mm256_setzero_si256(); ParBlocksSize::USIZE];
            unroll_par! {
                i, {
                    blocks[i] = _mm256_loadu_si256(in_ptr.add(i));
                }
            };

            let rk = _mm256_broadcastsi128_si256(k[0]);
            unroll_par! {
                i, {
                    let t = _mm256_xor_si256(blocks[i], rk);
                    let t = sub_bytes256(t, &P);
                    blocks[i] = transform2(t, &DEC_TABLE);
                }
            }

            for i in 1..9 {
                let rk = _mm256_broadcastsi128_si256(k[i]);
                unroll_par! {
                    j, {
                        let t = transform2(blocks[j], &DEC_TABLE);
                        blocks[j] = _mm256_xor_si256(t, rk);
                    }
                }
            }

            let rk = _mm256_broadcastsi128_si256(k[9]);
            unroll_par! {
                i, {
                    let t = sub_bytes256(blocks[i], &P_INV);
                    let t2 = _mm256_xor_si256(t, rk);
                    _mm256_storeu_si256(out_ptr.add(i), t2)
                }
            }
        }
    }
}
