use super::RoundKeys;
use crate::ni::arch::*;

use core::mem;

macro_rules! expand_round {
    ($enc_keys:expr, $dec_keys:expr, $pos:expr, $round:expr) => {
        let mut t1 = $enc_keys[$pos - 2];
        let mut t2;
        let mut t3 = $enc_keys[$pos - 1];
        let mut t4;

        t2 = _mm_aeskeygenassist_si128(t3, $round);
        t2 = _mm_shuffle_epi32(t2, 0xff);
        t4 = _mm_slli_si128(t1, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t4 = _mm_slli_si128(t4, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t4 = _mm_slli_si128(t4, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t1 = _mm_xor_si128(t1, t2);

        $enc_keys[$pos] = t1;
        $dec_keys[$pos] = _mm_aesimc_si128(t1);

        t4 = _mm_aeskeygenassist_si128(t1, 0x00);
        t2 = _mm_shuffle_epi32(t4, 0xaa);
        t4 = _mm_slli_si128(t3, 0x4);
        t3 = _mm_xor_si128(t3, t4);
        t4 = _mm_slli_si128(t4, 0x4);
        t3 = _mm_xor_si128(t3, t4);
        t4 = _mm_slli_si128(t4, 0x4);
        t3 = _mm_xor_si128(t3, t4);
        t3 = _mm_xor_si128(t3, t2);

        $enc_keys[$pos + 1] = t3;
        $dec_keys[$pos + 1] = _mm_aesimc_si128(t3);
    };
}

macro_rules! expand_round_last {
    ($enc_keys:expr, $dec_keys:expr, $pos:expr, $round:expr) => {
        let mut t1 = $enc_keys[$pos - 2];
        let mut t2;
        let t3 = $enc_keys[$pos - 1];
        let mut t4;

        t2 = _mm_aeskeygenassist_si128(t3, $round);
        t2 = _mm_shuffle_epi32(t2, 0xff);
        t4 = _mm_slli_si128(t1, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t4 = _mm_slli_si128(t4, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t4 = _mm_slli_si128(t4, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t1 = _mm_xor_si128(t1, t2);

        $enc_keys[$pos] = t1;
        $dec_keys[$pos] = t1;
    };
}

#[inline(always)]
pub(super) fn expand(key: &[u8; 32]) -> (RoundKeys, RoundKeys) {
    // Safety: `loadu` and `storeu` support unaligned access
    #[allow(clippy::cast_ptr_alignment)]
    unsafe {
        let mut enc_keys: RoundKeys = mem::zeroed();
        let mut dec_keys: RoundKeys = mem::zeroed();

        let kp = key.as_ptr() as *const __m128i;
        let k1 = _mm_loadu_si128(kp);
        let k2 = _mm_loadu_si128(kp.offset(1));
        enc_keys[0] = k1;
        dec_keys[0] = k1;
        enc_keys[1] = k2;
        dec_keys[1] = _mm_aesimc_si128(k2);

        expand_round!(enc_keys, dec_keys, 2, 0x01);
        expand_round!(enc_keys, dec_keys, 4, 0x02);
        expand_round!(enc_keys, dec_keys, 6, 0x04);
        expand_round!(enc_keys, dec_keys, 8, 0x08);
        expand_round!(enc_keys, dec_keys, 10, 0x10);
        expand_round!(enc_keys, dec_keys, 12, 0x20);
        expand_round_last!(enc_keys, dec_keys, 14, 0x40);

        (enc_keys, dec_keys)
    }
}
