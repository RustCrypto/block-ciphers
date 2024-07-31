//! AES encryption support
//!
//! Note that `aes` target feature implicitly enables `neon`, see:
//! https://doc.rust-lang.org/reference/attributes/codegen.html#aarch64

use crate::Block;
use cipher::{
    array::{Array, ArraySize},
    inout::InOut,
};
use core::{arch::aarch64::*, mem};

/// Perform AES encryption using the given expanded keys.
#[target_feature(enable = "aes")]
pub(super) unsafe fn encrypt<const KEYS: usize>(
    keys: &[uint8x16_t; KEYS],
    block: InOut<'_, '_, Block>,
) {
    assert!(KEYS == 11 || KEYS == 13 || KEYS == 15);
    let (in_ptr, out_ptr) = block.into_raw();
    let mut state = vld1q_u8(in_ptr.cast());

    for &key in &keys[..KEYS - 2] {
        // AES single round encryption
        state = vaeseq_u8(state, key);
        // Mix columns
        state = vaesmcq_u8(state);
    }

    // AES single round encryption
    state = vaeseq_u8(state, keys[KEYS - 2]);
    // Final add (bitwise XOR)
    state = veorq_u8(state, keys[KEYS - 1]);

    vst1q_u8(out_ptr.cast(), state);
}

/// Perform AES decryption using the given expanded keys.
#[target_feature(enable = "aes")]
pub(super) unsafe fn decrypt<const KEYS: usize>(
    keys: &[uint8x16_t; KEYS],
    block: InOut<'_, '_, Block>,
) {
    assert!(KEYS == 11 || KEYS == 13 || KEYS == 15);

    let (in_ptr, out_ptr) = block.into_raw();
    let mut state = vld1q_u8(in_ptr.cast());

    for &key in &keys[..KEYS - 2] {
        // AES single round decryption
        state = vaesdq_u8(state, key);
        // Inverse mix columns
        state = vaesimcq_u8(state);
    }

    // AES single round decryption
    state = vaesdq_u8(state, keys[KEYS - 2]);
    // Final add (bitwise XOR)
    state = veorq_u8(state, keys[KEYS - 1]);

    vst1q_u8(out_ptr.cast(), state);
}

/// Perform parallel AES encryption 8-blocks-at-a-time using the given expanded keys.
#[target_feature(enable = "aes")]
pub(super) unsafe fn encrypt_par<const KEYS: usize, ParBlocks: ArraySize>(
    keys: &[uint8x16_t; KEYS],
    blocks: InOut<'_, '_, Array<Block, ParBlocks>>,
) {
    #[inline(always)]
    unsafe fn par_round<ParBlocks: ArraySize>(
        key: uint8x16_t,
        state: &mut Array<uint8x16_t, ParBlocks>,
    ) {
        for s in state {
            // AES single round encryption and mix columns
            *s = vaesmcq_u8(vaeseq_u8(*s, key));
        }
    }

    assert!(KEYS == 11 || KEYS == 13 || KEYS == 15);

    let (in_ptr, out_ptr) = blocks.into_raw();
    let in_ptr: *const Block = in_ptr.cast();
    let out_ptr: *mut Block = out_ptr.cast();

    // Load plaintext blocks
    let mut state: Array<uint8x16_t, ParBlocks> = mem::zeroed();
    for i in 0..ParBlocks::USIZE {
        state[i] = vld1q_u8(in_ptr.add(i).cast());
    }

    // Loop is intentionally not used here to enforce inlining
    par_round(keys[0], &mut state);
    par_round(keys[1], &mut state);
    par_round(keys[2], &mut state);
    par_round(keys[3], &mut state);
    par_round(keys[4], &mut state);
    par_round(keys[5], &mut state);
    par_round(keys[6], &mut state);
    par_round(keys[7], &mut state);
    par_round(keys[8], &mut state);
    if KEYS >= 13 {
        par_round(keys[9], &mut state);
        par_round(keys[10], &mut state);
    }
    if KEYS == 15 {
        par_round(keys[11], &mut state);
        par_round(keys[12], &mut state);
    }

    for i in 0..ParBlocks::USIZE {
        // AES single round encryption
        state[i] = vaeseq_u8(state[i], keys[KEYS - 2]);
        // Final add (bitwise XOR)
        state[i] = veorq_u8(state[i], keys[KEYS - 1]);
        // Save encrypted blocks
        vst1q_u8(out_ptr.add(i).cast(), state[i]);
    }
}

/// Perform parallel AES decryption 8-blocks-at-a-time using the given expanded keys.
#[target_feature(enable = "aes")]
pub(super) unsafe fn decrypt_par<const KEYS: usize, ParBlocks: ArraySize>(
    keys: &[uint8x16_t; KEYS],
    blocks: InOut<'_, '_, Array<Block, ParBlocks>>,
) {
    #[inline(always)]
    unsafe fn par_round<ParBlocks: ArraySize>(
        key: uint8x16_t,
        state: &mut Array<uint8x16_t, ParBlocks>,
    ) {
        for s in state {
            // AES single round decryption and inverse mix columns
            *s = vaesimcq_u8(vaesdq_u8(*s, key));
        }
    }

    assert!(KEYS == 11 || KEYS == 13 || KEYS == 15);

    let (in_ptr, out_ptr) = blocks.into_raw();
    let in_ptr: *const Block = in_ptr.cast();
    let out_ptr: *mut Block = out_ptr.cast();

    // Load encrypted blocks
    let mut state: Array<uint8x16_t, ParBlocks> = mem::zeroed();
    for i in 0..ParBlocks::USIZE {
        state[i] = vld1q_u8(in_ptr.add(i).cast());
    }

    // Loop is intentionally not used here to enforce inlining
    par_round(keys[0], &mut state);
    par_round(keys[1], &mut state);
    par_round(keys[2], &mut state);
    par_round(keys[3], &mut state);
    par_round(keys[4], &mut state);
    par_round(keys[5], &mut state);
    par_round(keys[6], &mut state);
    par_round(keys[7], &mut state);
    par_round(keys[8], &mut state);
    if KEYS >= 13 {
        par_round(keys[9], &mut state);
        par_round(keys[10], &mut state);
    }
    if KEYS == 15 {
        par_round(keys[11], &mut state);
        par_round(keys[12], &mut state);
    }

    for i in 0..ParBlocks::USIZE {
        // AES single round decryption
        state[i] = vaesdq_u8(state[i], keys[KEYS - 2]);
        // Final add (bitwise XOR)
        state[i] = veorq_u8(state[i], keys[KEYS - 1]);
        // Save plaintext blocks
        vst1q_u8(out_ptr.add(i) as *mut u8, state[i]);
    }
}
