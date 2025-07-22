use crate::x86::{Block30, Simd128RoundKeys, Simd256RoundKeys, arch::*};
use cipher::inout::InOut;
use core::mem::MaybeUninit;

#[target_feature(enable = "avx2")]
#[inline]
pub(crate) unsafe fn broadcast_keys<const KEYS: usize>(
    keys: &Simd128RoundKeys<KEYS>,
) -> Simd256RoundKeys<KEYS> {
    keys.map(|key| _mm256_broadcastsi128_si256(key))
}

#[target_feature(enable = "avx2,vaes")]
#[inline]
pub(crate) unsafe fn encrypt30<const KEYS: usize>(
    keys: &Simd256RoundKeys<KEYS>,
    blocks: InOut<'_, '_, Block30>,
) {
    assert!(KEYS == 11 || KEYS == 13 || KEYS == 15);

    let (iptr, optr) = blocks.into_raw();
    let iptr = iptr.cast::<__m256i>();
    let optr = optr.cast::<__m256i>();

    let mut data: [MaybeUninit<__m256i>; 15] = unsafe { MaybeUninit::uninit().assume_init() };

    (0..15).for_each(|i| {
        data[i].write(unsafe { iptr.add(i).read_unaligned() });
    });
    let mut data: [__m256i; 15] = unsafe { ::core::mem::transmute(data) };

    for vec in &mut data {
        *vec = _mm256_xor_si256(*vec, keys[0]);
    }
    for key in &keys[1..KEYS - 1] {
        for vec in &mut data {
            *vec = _mm256_aesenc_epi128(*vec, *key);
        }
    }
    for vec in &mut data {
        *vec = _mm256_aesenclast_epi128(*vec, keys[KEYS - 1]);
    }

    (0..15).for_each(|i| {
        unsafe { optr.add(i).write_unaligned(data[i]) };
    });
}

#[target_feature(enable = "avx2,vaes")]
#[inline]
pub(crate) unsafe fn decrypt30<const KEYS: usize>(
    keys: &Simd256RoundKeys<KEYS>,
    blocks: InOut<'_, '_, Block30>,
) {
    assert!(KEYS == 11 || KEYS == 13 || KEYS == 15);

    let (iptr, optr) = blocks.into_raw();
    let iptr = iptr.cast::<__m256i>();
    let optr = optr.cast::<__m256i>();

    let mut data: [MaybeUninit<__m256i>; 15] = unsafe { MaybeUninit::uninit().assume_init() };

    (0..15).for_each(|i| {
        data[i].write(unsafe { iptr.add(i).read_unaligned() });
    });
    let mut data: [__m256i; 15] = unsafe { ::core::mem::transmute(data) };

    for vec in &mut data {
        *vec = _mm256_xor_si256(*vec, keys[0]);
    }
    for key in &keys[1..KEYS - 1] {
        for vec in &mut data {
            *vec = _mm256_aesdec_epi128(*vec, *key);
        }
    }
    for vec in &mut data {
        *vec = _mm256_aesdeclast_epi128(*vec, keys[KEYS - 1]);
    }

    (0..15).for_each(|i| {
        unsafe { optr.add(i).write_unaligned(data[i]) };
    });
}
