use arch::*;

use core::mem;

macro_rules! expand_round {
    ($enc_keys:expr, $dec_keys:expr, $pos:expr, $round:expr) => {
        let mut t1 = $enc_keys[$pos-2];
        let mut t2;
        let mut t3 = $enc_keys[$pos-1];
        let mut t4;
        unsafe {
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

            $enc_keys[$pos+1] = t3;
            $dec_keys[$pos+1] = _mm_aesimc_si128(t3);
        }
    }
}

macro_rules! expand_round_last {
    ($enc_keys:expr, $dec_keys:expr, $pos:expr, $round:expr) => {
        let mut t1 = $enc_keys[$pos-2];
        let mut t2;
        let t3 = $enc_keys[$pos-1];
        let mut t4;
        unsafe {
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
        }
    }
}

#[inline(always)]
pub(super) fn expand(key: &[u8; 32]) -> ([__m128i; 15], [__m128i; 15]) {
    let mut enc_keys: [__m128i; 15] = unsafe { mem::uninitialized() };
    let mut dec_keys: [__m128i; 15] = unsafe { mem::uninitialized() };

    unsafe {
        let kp = key.as_ptr();
        enc_keys[0] = _mm_loadu_si128(kp as *const __m128i);
        dec_keys[0] = enc_keys[0];
        enc_keys[1] = _mm_loadu_si128(kp.offset(16) as *const __m128i);
        dec_keys[1] = _mm_aesimc_si128(enc_keys[1]);
    }

    expand_round!(enc_keys, dec_keys, 2, 0x01);
    expand_round!(enc_keys, dec_keys, 4, 0x02);
    expand_round!(enc_keys, dec_keys, 6, 0x04);
    expand_round!(enc_keys, dec_keys, 8, 0x08);
    expand_round!(enc_keys, dec_keys, 10, 0x10);
    expand_round!(enc_keys, dec_keys, 12, 0x20);
    expand_round_last!(enc_keys, dec_keys, 14, 0x40);

    (enc_keys, dec_keys)
}
