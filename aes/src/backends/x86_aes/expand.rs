#![allow(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

pub(crate) type RoundKeys<const RK: usize> = [__m128i; RK];

#[inline]
#[target_feature(enable = "aes")]
pub(super) unsafe fn aes128_expand_key(key: &[u8; 16]) -> RoundKeys<11> {
    unsafe fn expand_round<const R: i32>(keys: &mut RoundKeys<11>, pos: usize) {
        let mut t1 = keys[pos - 1];
        let mut t2;
        let mut t3;

        t2 = _mm_aeskeygenassist_si128(t1, R);
        t2 = _mm_shuffle_epi32(t2, 0xff);
        t3 = _mm_slli_si128(t1, 0x4);
        t1 = _mm_xor_si128(t1, t3);
        t3 = _mm_slli_si128(t3, 0x4);
        t1 = _mm_xor_si128(t1, t3);
        t3 = _mm_slli_si128(t3, 0x4);
        t1 = _mm_xor_si128(t1, t3);
        t1 = _mm_xor_si128(t1, t2);

        keys[pos] = t1;
    }

    let mut keys = [_mm_setzero_si128(); 11];
    let k = _mm_loadu_si128(key.as_ptr().cast());
    keys[0] = k;

    let kr = &mut keys;
    expand_round::<0x01>(kr, 1);
    expand_round::<0x02>(kr, 2);
    expand_round::<0x04>(kr, 3);
    expand_round::<0x08>(kr, 4);
    expand_round::<0x10>(kr, 5);
    expand_round::<0x20>(kr, 6);
    expand_round::<0x40>(kr, 7);
    expand_round::<0x80>(kr, 8);
    expand_round::<0x1B>(kr, 9);
    expand_round::<0x36>(kr, 10);

    keys
}

#[inline]
#[target_feature(enable = "aes")]
pub(super) unsafe fn aes192_expand_key(key: &[u8; 24]) -> RoundKeys<13> {
    unsafe fn unpack_hilo(a: __m128i, b: __m128i) -> __m128i {
        let a = _mm_shuffle_epi32(a, 0b01_00_11_10);
        _mm_unpacklo_epi64(a, b)
    }

    #[target_feature(enable = "aes")]
    unsafe fn expand_round<const R: i32>(mut t1: __m128i, mut t3: __m128i) -> (__m128i, __m128i) {
        let (mut t2, mut t4);

        t2 = _mm_aeskeygenassist_si128(t3, R);
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

    let mut keys = [_mm_setzero_si128(); 13];
    // We are being extra pedantic here to remove out-of-bound access.
    // This should be optimized into movups, movsd sequence.
    let (k0, k1l) = {
        let mut t = [0u8; 32];
        t[..key.len()].copy_from_slice(key);
        (
            _mm_loadu_si128(t.as_ptr().cast()),
            _mm_loadu_si128(t.as_ptr().offset(16).cast()),
        )
    };

    keys[0] = k0;

    let (k1_2, k2r) = expand_round::<0x01>(k0, k1l);
    keys[1] = _mm_unpacklo_epi64(k1l, k1_2);
    keys[2] = unpack_hilo(k1_2, k2r);

    let (k3, k4l) = expand_round::<0x02>(k1_2, k2r);
    keys[3] = k3;

    let (k4_5, k5r) = expand_round::<0x04>(k3, k4l);
    let k4 = _mm_unpacklo_epi64(k4l, k4_5);
    let k5 = unpack_hilo(k4_5, k5r);
    keys[4] = k4;
    keys[5] = k5;

    let (k6, k7l) = expand_round::<0x08>(k4_5, k5r);
    keys[6] = k6;

    let (k7_8, k8r) = expand_round::<0x10>(k6, k7l);
    keys[7] = _mm_unpacklo_epi64(k7l, k7_8);
    keys[8] = unpack_hilo(k7_8, k8r);

    let (k9, k10l) = expand_round::<0x20>(k7_8, k8r);
    keys[9] = k9;

    let (k10_11, k11r) = expand_round::<0x40>(k9, k10l);
    keys[10] = _mm_unpacklo_epi64(k10l, k10_11);
    keys[11] = unpack_hilo(k10_11, k11r);

    let (k12, _) = expand_round::<0x80>(k10_11, k11r);
    keys[12] = k12;

    keys
}

#[inline]
#[target_feature(enable = "aes")]
pub(super) unsafe fn aes256_expand_key(key: &[u8; 32]) -> RoundKeys<15> {
    unsafe fn expand_round<const R: i32>(keys: &mut RoundKeys<15>, pos: usize) {
        let mut t1 = keys[pos - 2];
        let mut t2;
        let mut t3 = keys[pos - 1];
        let mut t4;

        t2 = _mm_aeskeygenassist_si128(t3, R);
        t2 = _mm_shuffle_epi32(t2, 0xff);
        t4 = _mm_slli_si128(t1, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t4 = _mm_slli_si128(t4, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t4 = _mm_slli_si128(t4, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t1 = _mm_xor_si128(t1, t2);

        keys[pos] = t1;

        t4 = _mm_aeskeygenassist_si128(t1, 0x00);
        t2 = _mm_shuffle_epi32(t4, 0xaa);
        t4 = _mm_slli_si128(t3, 0x4);
        t3 = _mm_xor_si128(t3, t4);
        t4 = _mm_slli_si128(t4, 0x4);
        t3 = _mm_xor_si128(t3, t4);
        t4 = _mm_slli_si128(t4, 0x4);
        t3 = _mm_xor_si128(t3, t4);
        t3 = _mm_xor_si128(t3, t2);

        keys[pos + 1] = t3;
    }

    unsafe fn expand_round_last<const R: i32>(keys: &mut RoundKeys<15>, pos: usize) {
        let mut t1 = keys[pos - 2];
        let mut t2;
        let t3 = keys[pos - 1];
        let mut t4;

        t2 = _mm_aeskeygenassist_si128(t3, R);
        t2 = _mm_shuffle_epi32(t2, 0xff);
        t4 = _mm_slli_si128(t1, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t4 = _mm_slli_si128(t4, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t4 = _mm_slli_si128(t4, 0x4);
        t1 = _mm_xor_si128(t1, t4);
        t1 = _mm_xor_si128(t1, t2);

        keys[pos] = t1;
    }

    let mut keys = [_mm_setzero_si128(); 15];

    let kp = key.as_ptr().cast::<__m128i>();
    keys[0] = _mm_loadu_si128(kp);
    keys[1] = _mm_loadu_si128(kp.add(1));

    let k = &mut keys;
    expand_round::<0x01>(k, 2);
    expand_round::<0x02>(k, 4);
    expand_round::<0x04>(k, 6);
    expand_round::<0x08>(k, 8);
    expand_round::<0x10>(k, 10);
    expand_round::<0x20>(k, 12);
    expand_round_last::<0x40>(k, 14);

    keys
}

#[inline]
#[target_feature(enable = "aes")]
pub(super) unsafe fn inv_expanded_keys<const N: usize>(keys: &[__m128i; N]) -> [__m128i; N] {
    let mut inv_keys: [__m128i; N] = [_mm_setzero_si128(); N];
    inv_keys[0] = keys[N - 1];
    for i in 1..N - 1 {
        inv_keys[i] = _mm_aesimc_si128(keys[N - 1 - i]);
    }
    inv_keys[N - 1] = keys[0];
    inv_keys
}
