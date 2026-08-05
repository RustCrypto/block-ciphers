//! AES encryption support
//!
//! Note that `aes` target feature implicitly enables `neon`, see:
//! https://doc.rust-lang.org/reference/attributes/codegen.html#r-attributes.codegen.target_feature.aarch64
use super::utils::{load_block, store_block};
use crate::Block;
use cipher::{
    array::{Array, ArraySize},
    inout::InOut,
};
use core::arch::aarch64::*;

#[target_feature(enable = "aes")]
#[inline]
pub(super) fn encrypt<const RK: usize>(keys: &[uint8x16_t; RK], mut block: InOut<'_, '_, Block>) {
    const { assert!(matches!(RK, 11 | 13 | 15)) }

    let mut b = load_block(block.get_in());

    for &key in &keys[..RK - 2] {
        // AES single round encryption
        b = vaeseq_u8(b, key);
        // Mix columns
        b = vaesmcq_u8(b);
    }

    // AES single round encryption
    b = vaeseq_u8(b, keys[RK - 2]);
    // Final add (bitwise XOR)
    b = veorq_u8(b, keys[RK - 1]);

    store_block(block.get_out(), b);
}

#[target_feature(enable = "aes")]
#[inline]
pub(super) fn decrypt<const RK: usize>(keys: &[uint8x16_t; RK], mut block: InOut<'_, '_, Block>) {
    const { assert!(matches!(RK, 11 | 13 | 15)) }

    let mut b = load_block(block.get_in());

    for &key in &keys[..RK - 2] {
        // AES single round decryption
        b = vaesdq_u8(b, key);
        // Inverse mix columns
        b = vaesimcq_u8(b);
    }

    // AES single round decryption
    b = vaesdq_u8(b, keys[RK - 2]);
    // Final add (bitwise XOR)
    b = veorq_u8(b, keys[RK - 1]);

    store_block(block.get_out(), b);
}

#[target_feature(enable = "aes")]
#[inline]
pub(super) fn batch_encrypt<const RK: usize, ParBlocks: ArraySize>(
    keys: &[uint8x16_t; RK],
    mut blocks: InOut<'_, '_, Array<Block, ParBlocks>>,
) {
    const { assert!(matches!(RK, 11 | 13 | 15)) }

    let mut b = load_batch_blocks(blocks.get_in());

    // Loop is intentionally not used here to enforce inlining
    batch_enc_round(keys[0], &mut b);
    batch_enc_round(keys[1], &mut b);
    batch_enc_round(keys[2], &mut b);
    batch_enc_round(keys[3], &mut b);
    batch_enc_round(keys[4], &mut b);
    batch_enc_round(keys[5], &mut b);
    batch_enc_round(keys[6], &mut b);
    batch_enc_round(keys[7], &mut b);
    batch_enc_round(keys[8], &mut b);
    if RK >= 13 {
        batch_enc_round(keys[9], &mut b);
        batch_enc_round(keys[10], &mut b);
    }
    if RK == 15 {
        batch_enc_round(keys[11], &mut b);
        batch_enc_round(keys[12], &mut b);
    }

    for i in 0..ParBlocks::USIZE {
        b[i] = vaeseq_u8(b[i], keys[RK - 2]);
        b[i] = veorq_u8(b[i], keys[RK - 1]);
        store_block(&mut blocks.get_out()[i], b[i]);
    }
}

#[target_feature(enable = "aes")]
#[inline]
pub(super) fn batch_decrypt<const RK: usize, ParBlocks: ArraySize>(
    keys: &[uint8x16_t; RK],
    mut blocks: InOut<'_, '_, Array<Block, ParBlocks>>,
) {
    const { assert!(matches!(RK, 11 | 13 | 15)) }

    let mut b = load_batch_blocks(blocks.get_in());

    // Loop is intentionally not used here to enforce inlining
    batch_dec_round(keys[0], &mut b);
    batch_dec_round(keys[1], &mut b);
    batch_dec_round(keys[2], &mut b);
    batch_dec_round(keys[3], &mut b);
    batch_dec_round(keys[4], &mut b);
    batch_dec_round(keys[5], &mut b);
    batch_dec_round(keys[6], &mut b);
    batch_dec_round(keys[7], &mut b);
    batch_dec_round(keys[8], &mut b);
    if RK >= 13 {
        batch_dec_round(keys[9], &mut b);
        batch_dec_round(keys[10], &mut b);
    }
    if RK == 15 {
        batch_dec_round(keys[11], &mut b);
        batch_dec_round(keys[12], &mut b);
    }

    for i in 0..ParBlocks::USIZE {
        b[i] = vaesdq_u8(b[i], keys[RK - 2]);
        b[i] = veorq_u8(b[i], keys[RK - 1]);
        store_block(&mut blocks.get_out()[i], b[i]);
    }
}

#[target_feature(enable = "aes")]
fn batch_enc_round<ParBlocks: ArraySize>(
    key: uint8x16_t,
    blocks: &mut Array<uint8x16_t, ParBlocks>,
) {
    for block in blocks {
        *block = vaesmcq_u8(vaeseq_u8(*block, key));
    }
}

#[target_feature(enable = "aes")]
fn batch_dec_round<ParBlocks: ArraySize>(
    key: uint8x16_t,
    blocks: &mut Array<uint8x16_t, ParBlocks>,
) {
    for block in blocks {
        *block = vaesimcq_u8(vaesdq_u8(*block, key));
    }
}

#[target_feature(enable = "neon")]
fn load_batch_blocks<N: ArraySize>(blocks: &Array<Block, N>) -> Array<uint8x16_t, N> {
    Array::from_fn(|i| load_block(&blocks[i]))
}
