#![allow(unsafe_op_in_unsafe_fn)]

use super::RoundKeys;
use crate::Block;
use cipher::{
    array::{Array, ArraySize},
    inout::InOut,
};

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[inline]
#[target_feature(enable = "aes")]
pub(crate) unsafe fn encrypt<const RK: usize>(keys: &RoundKeys<RK>, block: InOut<'_, '_, Block>) {
    const { assert!(matches!(RK, 11 | 13 | 15)) }

    let (block_in, block_out) = block.into_raw();
    let mut b = _mm_loadu_si128(block_in.cast());
    b = _mm_xor_si128(b, keys[0]);
    for &key in &keys[1..RK - 1] {
        b = _mm_aesenc_si128(b, key);
    }
    b = _mm_aesenclast_si128(b, keys[RK - 1]);
    _mm_storeu_si128(block_out.cast(), b);
}

#[inline]
#[target_feature(enable = "aes")]
pub(crate) unsafe fn decrypt<const RK: usize>(keys: &RoundKeys<RK>, block: InOut<'_, '_, Block>) {
    const { assert!(matches!(RK, 11 | 13 | 15)) }

    let (block_in, block_out) = block.into_raw();
    let mut b = _mm_loadu_si128(block_in.cast());
    b = _mm_xor_si128(b, keys[0]);
    for &key in &keys[1..RK - 1] {
        b = _mm_aesdec_si128(b, key);
    }
    b = _mm_aesdeclast_si128(b, keys[RK - 1]);
    _mm_storeu_si128(block_out.cast(), b);
}

#[inline]
#[target_feature(enable = "aes")]
pub(super) unsafe fn encrypt_par<const RK: usize, ParBlocks: ArraySize>(
    keys: &RoundKeys<RK>,
    mut blocks: InOut<'_, '_, Array<Block, ParBlocks>>,
) {
    const { assert!(matches!(RK, 11 | 13 | 15)) }

    let mut b = load(blocks.get_in());

    // Loop over keys is intentionally not used here to force inlining
    xor(&mut b, keys[0]);
    aesenc(&mut b, keys[1]);
    aesenc(&mut b, keys[2]);
    aesenc(&mut b, keys[3]);
    aesenc(&mut b, keys[4]);
    aesenc(&mut b, keys[5]);
    aesenc(&mut b, keys[6]);
    aesenc(&mut b, keys[7]);
    aesenc(&mut b, keys[8]);
    aesenc(&mut b, keys[9]);
    if RK >= 13 {
        aesenc(&mut b, keys[10]);
        aesenc(&mut b, keys[11]);
    }
    if RK == 15 {
        aesenc(&mut b, keys[12]);
        aesenc(&mut b, keys[13]);
    }
    aesenclast(&mut b, keys[RK - 1]);
    store(blocks.get_out(), b);
}

#[inline]
#[target_feature(enable = "aes")]
pub(super) unsafe fn decrypt_par<const RK: usize, ParBlocks: ArraySize>(
    keys: &RoundKeys<RK>,
    mut blocks: InOut<'_, '_, Array<Block, ParBlocks>>,
) {
    const { assert!(matches!(RK, 11 | 13 | 15)) };

    let mut b = load(blocks.get_in());

    // Loop over keys is intentionally not used here to force inlining
    xor(&mut b, keys[0]);
    aesdec(&mut b, keys[1]);
    aesdec(&mut b, keys[2]);
    aesdec(&mut b, keys[3]);
    aesdec(&mut b, keys[4]);
    aesdec(&mut b, keys[5]);
    aesdec(&mut b, keys[6]);
    aesdec(&mut b, keys[7]);
    aesdec(&mut b, keys[8]);
    aesdec(&mut b, keys[9]);
    if RK >= 13 {
        aesdec(&mut b, keys[10]);
        aesdec(&mut b, keys[11]);
    }
    if RK == 15 {
        aesdec(&mut b, keys[12]);
        aesdec(&mut b, keys[13]);
    }
    aesdeclast(&mut b, keys[RK - 1]);
    store(blocks.get_out(), b);
}

#[target_feature(enable = "sse2")]
pub(crate) unsafe fn load<N: ArraySize>(blocks: &Array<Block, N>) -> Array<__m128i, N> {
    let p: *const __m128i = blocks.as_ptr().cast();
    Array::from_fn(|i| unsafe { _mm_loadu_si128(p.add(i)) })
}

#[target_feature(enable = "sse2")]
pub(crate) unsafe fn store<N: ArraySize>(dst: &mut Array<Block, N>, blocks: Array<__m128i, N>) {
    let p: *mut __m128i = dst.as_mut_ptr().cast();
    for (i, block) in blocks.into_iter().enumerate() {
        unsafe { _mm_storeu_si128(p.add(i), block) }
    }
}

#[target_feature(enable = "sse2")]
pub(crate) unsafe fn xor<N: ArraySize>(blocks: &mut Array<__m128i, N>, key: __m128i) {
    for block in blocks {
        *block = _mm_xor_si128(*block, key);
    }
}

#[target_feature(enable = "aes")]
pub(crate) unsafe fn aesenc<N: ArraySize>(blocks: &mut Array<__m128i, N>, key: __m128i) {
    for block in blocks {
        *block = _mm_aesenc_si128(*block, key);
    }
}

#[target_feature(enable = "aes")]
pub(crate) unsafe fn aesenclast<N: ArraySize>(blocks: &mut Array<__m128i, N>, key: __m128i) {
    for block in blocks {
        *block = _mm_aesenclast_si128(*block, key);
    }
}

#[target_feature(enable = "aes")]
pub(crate) unsafe fn aesdec<N: ArraySize>(blocks: &mut Array<__m128i, N>, key: __m128i) {
    for block in blocks {
        *block = _mm_aesdec_si128(*block, key);
    }
}

#[target_feature(enable = "aes")]
pub(crate) unsafe fn aesdeclast<N: ArraySize>(blocks: &mut Array<__m128i, N>, key: __m128i) {
    for block in blocks {
        *block = _mm_aesdeclast_si128(*block, key);
    }
}
