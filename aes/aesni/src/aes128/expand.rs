use arch::*;

use core::mem;

macro_rules! expand_round {
    ($enc_keys:expr, $dec_keys:expr, $pos:expr, $round:expr) => {
        let mut t1 = $enc_keys[$pos-1];
        let mut t2;
        let mut t3;
        unsafe {
            t2 = _mm_aeskeygenassist_si128(t1, $round);
            t2 = _mm_shuffle_epi32(t2, 0xff);
            t3 = _mm_slli_si128(t1, 0x4);
            t1 = _mm_xor_si128(t1, t3);
            t3 = _mm_slli_si128(t3, 0x4);
            t1 = _mm_xor_si128(t1, t3);
            t3 = _mm_slli_si128(t3, 0x4);
            t1 = _mm_xor_si128(t1, t3);
            t1 = _mm_xor_si128(t1, t2);

            $enc_keys[$pos] = t1;
            $dec_keys[$pos] = if $pos != 10 {
                _mm_aesimc_si128(t1)
            } else {
                t1
            };
        }
    }
}

#[inline(always)]
pub(super) fn expand(key: &[u8; 16]) -> ([__m128i; 11], [__m128i; 11]) {
    let mut enc_keys: [__m128i; 11] = unsafe { mem::uninitialized() };
    let mut dec_keys: [__m128i; 11] = unsafe { mem::uninitialized() };

    enc_keys[0] = unsafe { _mm_loadu_si128(key.as_ptr() as *const __m128i) };
    dec_keys[0] = enc_keys[0];

    expand_round!(enc_keys, dec_keys, 1, 0x01);
    expand_round!(enc_keys, dec_keys, 2, 0x02);
    expand_round!(enc_keys, dec_keys, 3, 0x04);
    expand_round!(enc_keys, dec_keys, 4, 0x08);
    expand_round!(enc_keys, dec_keys, 5, 0x10);
    expand_round!(enc_keys, dec_keys, 6, 0x20);
    expand_round!(enc_keys, dec_keys, 7, 0x40);
    expand_round!(enc_keys, dec_keys, 8, 0x80);
    expand_round!(enc_keys, dec_keys, 9, 0x1B);
    expand_round!(enc_keys, dec_keys, 10, 0x36);

    (enc_keys, dec_keys)
}
