//! Low-level "hazmat" AES functions: AES-NI support.
//!
//! Note: this isn't actually used in the `Aes128`/`Aes192`/`Aes256`
//! implementations in this crate, but instead provides raw AES-NI accelerated
//! access to the AES round function gated under the `hazmat` crate feature.
use super::utils;
use crate::hazmat::{Block, Block8};

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// AES cipher (encrypt) round function.
#[target_feature(enable = "aes")]
pub(crate) fn cipher_round(block: &mut Block, round_key: &Block) {
    // Safety: `loadu` and `storeu` support unaligned access
    let b = utils::load_block(block);
    let k = utils::load_block(round_key);
    let b = _mm_aesenc_si128(b, k);
    utils::store_block(block, b);
}

/// AES cipher (encrypt) round function: parallel version.
#[target_feature(enable = "aes")]
pub(crate) fn cipher_round_par(blocks: &mut Block8, round_keys: &Block8) {
    let rks = utils::load_batch_blocks(round_keys);
    let mut bb = utils::load_batch_blocks(blocks);

    for i in 0..bb.len() {
        bb[i] = _mm_aesenc_si128(bb[i], rks[i]);
    }

    utils::store_batch_blocks(blocks, bb);
}

/// AES cipher (encrypt) round function.
#[target_feature(enable = "aes")]
pub(crate) fn equiv_inv_cipher_round(block: &mut Block, round_key: &Block) {
    let b = utils::load_block(block);
    let rk = utils::load_block(round_key);
    let b = _mm_aesdec_si128(b, rk);
    utils::store_block(block, b);
}

/// AES cipher (encrypt) round function: parallel version.
#[target_feature(enable = "aes")]
pub(crate) fn equiv_inv_cipher_round_par(blocks: &mut Block8, round_keys: &Block8) {
    let rks = utils::load_batch_blocks(round_keys);
    let mut bb = utils::load_batch_blocks(blocks);

    for i in 0..bb.len() {
        bb[i] = _mm_aesdec_si128(bb[i], rks[i]);
    }

    utils::store_batch_blocks(blocks, bb);
}

/// AES mix columns function.
#[target_feature(enable = "aes")]
pub(crate) fn mix_columns(block: &mut Block) {
    // Safety: `loadu` and `storeu` support unaligned access
    let mut state = utils::load_block(block);

    // Emulate mix columns by performing three inverse mix columns operations
    state = _mm_aesimc_si128(state);
    state = _mm_aesimc_si128(state);
    state = _mm_aesimc_si128(state);

    utils::store_block(block, state);
}

/// AES inverse mix columns function.
#[target_feature(enable = "aes")]
pub(crate) fn inv_mix_columns(block: &mut Block) {
    let b = utils::load_block(block);
    let b = _mm_aesimc_si128(b);
    utils::store_block(block, b);
}
