//! AES encryption support

use crate::{Block, Block8};
use cipher::inout::InOut;
use core::arch::aarch64::*;

/// Perform AES encryption using the given expanded keys.
#[target_feature(enable = "aes")]
#[target_feature(enable = "neon")]
pub(super) unsafe fn encrypt1<const N: usize>(
    expanded_keys: &[uint8x16_t; N],
    block: InOut<'_, '_, Block>,
) {
    let rounds = N - 1;
    assert!(rounds == 10 || rounds == 12 || rounds == 14);

    let (in_ptr, out_ptr) = block.into_raw();

    let mut state = vld1q_u8(in_ptr as *const u8);

    for k in expanded_keys.iter().take(rounds - 1) {
        // AES single round encryption
        state = vaeseq_u8(state, *k);

        // Mix columns
        state = vaesmcq_u8(state);
    }

    // AES single round encryption
    state = vaeseq_u8(state, expanded_keys[rounds - 1]);

    // Final add (bitwise XOR)
    state = veorq_u8(state, expanded_keys[rounds]);

    vst1q_u8(out_ptr as *mut u8, state);
}

/// Perform parallel AES encryption 8-blocks-at-a-time using the given expanded keys.
#[target_feature(enable = "aes")]
#[target_feature(enable = "neon")]
pub(super) unsafe fn encrypt8<const N: usize>(
    expanded_keys: &[uint8x16_t; N],
    blocks: InOut<'_, '_, Block8>,
) {
    let rounds = N - 1;
    assert!(rounds == 10 || rounds == 12 || rounds == 14);

    let (in_ptr, out_ptr) = blocks.into_raw();
    let in_ptr = in_ptr as *const Block;
    let out_ptr = out_ptr as *const Block;

    let mut state = [
        vld1q_u8(in_ptr.add(0) as *const u8),
        vld1q_u8(in_ptr.add(1) as *const u8),
        vld1q_u8(in_ptr.add(2) as *const u8),
        vld1q_u8(in_ptr.add(3) as *const u8),
        vld1q_u8(in_ptr.add(4) as *const u8),
        vld1q_u8(in_ptr.add(5) as *const u8),
        vld1q_u8(in_ptr.add(6) as *const u8),
        vld1q_u8(in_ptr.add(7) as *const u8),
    ];

    for k in expanded_keys.iter().take(rounds - 1) {
        for i in 0..8 {
            // AES single round encryption
            state[i] = vaeseq_u8(state[i], *k);

            // Mix columns
            state[i] = vaesmcq_u8(state[i]);
        }
    }

    for i in 0..8 {
        // AES single round encryption
        state[i] = vaeseq_u8(state[i], expanded_keys[rounds - 1]);

        // Final add (bitwise XOR)
        state[i] = veorq_u8(state[i], expanded_keys[rounds]);

        vst1q_u8(out_ptr.add(i) as *mut u8, state[i]);
    }
}

/// Perform AES decryption using the given expanded keys.
#[target_feature(enable = "aes")]
#[target_feature(enable = "neon")]
pub(super) unsafe fn decrypt1<const N: usize>(
    expanded_keys: &[uint8x16_t; N],
    block: InOut<'_, '_, Block>,
) {
    let rounds = N - 1;
    assert!(rounds == 10 || rounds == 12 || rounds == 14);

    let (in_ptr, out_ptr) = block.into_raw();
    let mut state = vld1q_u8(in_ptr as *const u8);

    for k in expanded_keys.iter().take(rounds - 1) {
        // AES single round decryption
        state = vaesdq_u8(state, *k);

        // Inverse mix columns
        state = vaesimcq_u8(state);
    }

    // AES single round decryption
    state = vaesdq_u8(state, expanded_keys[rounds - 1]);

    // Final add (bitwise XOR)
    state = veorq_u8(state, expanded_keys[rounds]);

    vst1q_u8(out_ptr as *mut u8, state);
}

/// Perform parallel AES decryption 8-blocks-at-a-time using the given expanded keys.
#[target_feature(enable = "aes")]
#[target_feature(enable = "neon")]
pub(super) unsafe fn decrypt8<const N: usize>(
    expanded_keys: &[uint8x16_t; N],
    blocks: InOut<'_, '_, Block8>,
) {
    let rounds = N - 1;
    assert!(rounds == 10 || rounds == 12 || rounds == 14);

    let (in_ptr, out_ptr) = blocks.into_raw();
    let in_ptr = in_ptr as *const Block;
    let out_ptr = out_ptr as *const Block;

    let mut state = [
        vld1q_u8(in_ptr.add(0) as *const u8),
        vld1q_u8(in_ptr.add(1) as *const u8),
        vld1q_u8(in_ptr.add(2) as *const u8),
        vld1q_u8(in_ptr.add(3) as *const u8),
        vld1q_u8(in_ptr.add(4) as *const u8),
        vld1q_u8(in_ptr.add(5) as *const u8),
        vld1q_u8(in_ptr.add(6) as *const u8),
        vld1q_u8(in_ptr.add(7) as *const u8),
    ];

    for k in expanded_keys.iter().take(rounds - 1) {
        for i in 0..8 {
            // AES single round decryption
            state[i] = vaesdq_u8(state[i], *k);

            // Inverse mix columns
            state[i] = vaesimcq_u8(state[i]);
        }
    }

    for i in 0..8 {
        // AES single round decryption
        state[i] = vaesdq_u8(state[i], expanded_keys[rounds - 1]);

        // Final add (bitwise XOR)
        state[i] = veorq_u8(state[i], expanded_keys[rounds]);

        vst1q_u8(out_ptr.add(i) as *mut u8, state[i]);
    }
}
