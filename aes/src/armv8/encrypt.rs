//! AES encryption support

use crate::{Block, ParBlocks};
use core::arch::aarch64::*;

/// Perform AES encryption using the given expanded keys.
#[target_feature(enable = "aes")]
#[target_feature(enable = "neon")]
pub(super) unsafe fn encrypt<const N: usize>(expanded_keys: &[uint8x16_t; N], block: &mut Block) {
    let rounds = N - 1;
    assert!(rounds == 10 || rounds == 12 || rounds == 14);

    let mut state = vld1q_u8(block.as_ptr());

    for k in expanded_keys.iter().take(rounds - 1) {
        // AES single round encryption
        state = vaeseq_u8(state, *k);

        // AES mix columns
        state = vaesmcq_u8(state);
    }

    // AES single round encryption
    state = vaeseq_u8(state, expanded_keys[rounds - 1]);

    // Final add (bitwise XOR)
    state = veorq_u8(state, expanded_keys[rounds]);

    vst1q_u8(block.as_mut_ptr(), state);
}

/// Perform parallel AES encryption 8-blocks-at-a-time using the given expanded keys.
#[target_feature(enable = "aes")]
#[target_feature(enable = "neon")]
pub(super) unsafe fn encrypt8<const N: usize>(
    expanded_keys: &[uint8x16_t; N],
    blocks: &mut ParBlocks,
) {
    let rounds = N - 1;
    assert!(rounds == 10 || rounds == 12 || rounds == 14);

    let mut state = [
        vld1q_u8(blocks[0].as_ptr()),
        vld1q_u8(blocks[1].as_ptr()),
        vld1q_u8(blocks[2].as_ptr()),
        vld1q_u8(blocks[3].as_ptr()),
        vld1q_u8(blocks[4].as_ptr()),
        vld1q_u8(blocks[5].as_ptr()),
        vld1q_u8(blocks[6].as_ptr()),
        vld1q_u8(blocks[7].as_ptr()),
    ];

    for k in expanded_keys.iter().take(rounds - 1) {
        for i in 0..8 {
            // AES single round encryption
            state[i] = vaeseq_u8(state[i], *k);

            // AES mix columns
            state[i] = vaesmcq_u8(state[i]);
        }
    }

    for i in 0..8 {
        // AES single round encryption
        state[i] = vaeseq_u8(state[i], expanded_keys[rounds - 1]);

        // Final add (bitwise XOR)
        state[i] = veorq_u8(state[i], expanded_keys[rounds]);

        vst1q_u8(blocks[i].as_mut_ptr(), state[i]);
    }
}
