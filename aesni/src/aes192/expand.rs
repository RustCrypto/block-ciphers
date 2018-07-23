use arch::*;

use core::mem;

macro_rules! expand_round {
    ($t1:expr, $t3:expr, $round:expr) => {
        unsafe {
            let mut t1 = $t1;
            let mut t2;
            let mut t3 = $t3;
            let mut t4;

            t2 = _mm_aeskeygenassist_si128(t3, $round);
            t2 = _mm_shuffle_epi32(t2, 0x55);
            t4 = _mm_slli_si128(t1, 0x4);
            t1 = _mm_xor_si128(t1, t4);
            t4 = _mm_slli_si128(t4, 0x4);
            t1 = _mm_xor_si128(t1, t4);
            t4 = _mm_slli_si128(t4, 0x4);
            t1 = _mm_xor_si128(t1, t4);
            t1 = _mm_xor_si128(t1, t2);
            t2 = _mm_shuffle_epi32(t1, 0xff);
            t4 = _mm_slli_si128(t3, 0x4);
            t3 = _mm_xor_si128(t3, t4);
            t3 = _mm_xor_si128(t3, t2);

            (t1, t3)
        }
    }
}

macro_rules! shuffle {
    ($a:expr, $b:expr, $imm:expr) => {
        unsafe {
            mem::transmute::<_, __m128i>(
                _mm_shuffle_pd(mem::transmute($a), mem::transmute($b), $imm)
            )
        }
    }
}

#[inline(always)]
pub(super) fn expand(key: &[u8; 24]) -> ([__m128i; 13], [__m128i; 13]) {
    let mut enc_keys: [__m128i; 13] = unsafe { mem::uninitialized() };
    let mut dec_keys: [__m128i; 13] = unsafe { mem::uninitialized() };

    let (t1, t3) = unsafe {
        (
            _mm_loadu_si128(key.as_ptr() as *const __m128i),
            // we copy garbage for second half, it will be overwritten, so it's fine
            _mm_loadu_si128(key.as_ptr().offset(16) as *const __m128i),
        )
    };
    enc_keys[0] = t1;
    enc_keys[1] = t3;

    let (t1, t3) = expand_round!(t1, t3, 0x01);
    enc_keys[1] = shuffle!(enc_keys[1], t1, 0);
    enc_keys[2] = shuffle!(t1, t3, 1);
    let (t1, t3) = expand_round!(t1, t3, 0x02);
    enc_keys[3] = t1;
    enc_keys[4] = t3;

    let (t1, t3) = expand_round!(t1, t3, 0x04);
    enc_keys[4] = shuffle!(enc_keys[4], t1, 0);
    enc_keys[5] = shuffle!(t1, t3, 1);
    let (t1, t3) = expand_round!(t1, t3, 0x08);
    enc_keys[6] = t1;
    enc_keys[7] = t3;

    let (t1, t3) = expand_round!(t1, t3, 0x10);
    enc_keys[7] = shuffle!(enc_keys[7], t1, 0);
    enc_keys[8] = shuffle!(t1, t3, 1);
    let (t1, t3) = expand_round!(t1, t3, 0x20);
    enc_keys[9] = t1;
    enc_keys[10] = t3;

    let (t1, t3) = expand_round!(t1, t3, 0x40);
    enc_keys[10] = shuffle!(enc_keys[10], t1, 0);
    enc_keys[11] = shuffle!(t1, t3, 1);
    let (t1, _) = expand_round!(t1, t3, 0x80);
    enc_keys[12] = t1;

    dec_keys[0] = enc_keys[0];
    for i in 1..12 {
        dec_keys[i] = unsafe { _mm_aesimc_si128(enc_keys[i]) };
    }
    dec_keys[12] = enc_keys[12];

    (enc_keys, dec_keys)
}
