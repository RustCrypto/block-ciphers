use super::{RoundKeys, utils};
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
pub(crate) fn encrypt<const RK: usize>(keys: &RoundKeys<RK>, mut block: InOut<'_, '_, Block>) {
    const { assert!(matches!(RK, 11 | 13 | 15)) }

    let mut b = utils::load_block(block.get_in());
    b = _mm_xor_si128(b, keys[0]);
    for &key in &keys[1..RK - 1] {
        b = _mm_aesenc_si128(b, key);
    }
    b = _mm_aesenclast_si128(b, keys[RK - 1]);
    utils::store_block(block.get_out(), b);
}

#[inline]
#[target_feature(enable = "aes")]
pub(crate) fn decrypt<const RK: usize>(keys: &RoundKeys<RK>, mut block: InOut<'_, '_, Block>) {
    const { assert!(matches!(RK, 11 | 13 | 15)) }

    let mut b = utils::load_block(block.get_in());
    b = _mm_xor_si128(b, keys[0]);
    for &key in &keys[1..RK - 1] {
        b = _mm_aesdec_si128(b, key);
    }
    b = _mm_aesdeclast_si128(b, keys[RK - 1]);
    utils::store_block(block.get_out(), b);
}

#[inline]
#[target_feature(enable = "aes")]
pub(super) fn batch_encrypt<const RK: usize, ParBlocks: ArraySize>(
    keys: &RoundKeys<RK>,
    mut blocks: InOut<'_, '_, Array<Block, ParBlocks>>,
) {
    const { assert!(matches!(RK, 11 | 13 | 15)) }

    let mut b = utils::load_batch_blocks(blocks.get_in());

    // Loop over keys is intentionally not used here to force inlining
    batch_xor(&mut b, keys[0]);
    batch_aesenc(&mut b, keys[1]);
    batch_aesenc(&mut b, keys[2]);
    batch_aesenc(&mut b, keys[3]);
    batch_aesenc(&mut b, keys[4]);
    batch_aesenc(&mut b, keys[5]);
    batch_aesenc(&mut b, keys[6]);
    batch_aesenc(&mut b, keys[7]);
    batch_aesenc(&mut b, keys[8]);
    batch_aesenc(&mut b, keys[9]);
    if RK >= 13 {
        batch_aesenc(&mut b, keys[10]);
        batch_aesenc(&mut b, keys[11]);
    }
    if RK == 15 {
        batch_aesenc(&mut b, keys[12]);
        batch_aesenc(&mut b, keys[13]);
    }
    batch_aesenclast(&mut b, keys[RK - 1]);
    utils::store_batch_blocks(blocks.get_out(), b);
}

#[inline]
#[target_feature(enable = "aes")]
pub(super) fn decrypt_par<const RK: usize, ParBlocks: ArraySize>(
    keys: &RoundKeys<RK>,
    mut blocks: InOut<'_, '_, Array<Block, ParBlocks>>,
) {
    const { assert!(matches!(RK, 11 | 13 | 15)) };

    let mut b = utils::load_batch_blocks(blocks.get_in());

    // Loop over keys is intentionally not used here to force inlining
    batch_xor(&mut b, keys[0]);
    batch_aesdec(&mut b, keys[1]);
    batch_aesdec(&mut b, keys[2]);
    batch_aesdec(&mut b, keys[3]);
    batch_aesdec(&mut b, keys[4]);
    batch_aesdec(&mut b, keys[5]);
    batch_aesdec(&mut b, keys[6]);
    batch_aesdec(&mut b, keys[7]);
    batch_aesdec(&mut b, keys[8]);
    batch_aesdec(&mut b, keys[9]);
    if RK >= 13 {
        batch_aesdec(&mut b, keys[10]);
        batch_aesdec(&mut b, keys[11]);
    }
    if RK == 15 {
        batch_aesdec(&mut b, keys[12]);
        batch_aesdec(&mut b, keys[13]);
    }
    batch_aesdeclast(&mut b, keys[RK - 1]);
    utils::store_batch_blocks(blocks.get_out(), b);
}

#[target_feature(enable = "sse2")]
fn batch_xor<N: ArraySize>(blocks: &mut Array<__m128i, N>, key: __m128i) {
    for block in blocks {
        *block = _mm_xor_si128(*block, key);
    }
}

#[target_feature(enable = "aes")]
fn batch_aesenc<N: ArraySize>(blocks: &mut Array<__m128i, N>, key: __m128i) {
    for block in blocks {
        *block = _mm_aesenc_si128(*block, key);
    }
}

#[target_feature(enable = "aes")]
fn batch_aesenclast<N: ArraySize>(blocks: &mut Array<__m128i, N>, key: __m128i) {
    for block in blocks {
        *block = _mm_aesenclast_si128(*block, key);
    }
}

#[target_feature(enable = "aes")]
fn batch_aesdec<N: ArraySize>(blocks: &mut Array<__m128i, N>, key: __m128i) {
    for block in blocks {
        *block = _mm_aesdec_si128(*block, key);
    }
}

#[target_feature(enable = "aes")]
fn batch_aesdeclast<N: ArraySize>(blocks: &mut Array<__m128i, N>, key: __m128i) {
    for block in blocks {
        *block = _mm_aesdeclast_si128(*block, key);
    }
}
