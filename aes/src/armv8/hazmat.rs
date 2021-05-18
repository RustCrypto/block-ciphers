//! Low-level "hazmat" AES functions: ARMv8 Cryptography Extensions support.
//!
//! Note: this isn't actually used in the `Aes128`/`Aes192`/`Aes256`
//! implementations in this crate, but instead provides raw AES-NI accelerated
//! access to the AES round function gated under the `hazmat` crate feature.

use super::vst1q_u8;
use crate::Block;
use core::arch::aarch64::*;

/// AES cipher (encrypt) round function.
#[allow(clippy::cast_ptr_alignment)]
#[target_feature(enable = "crypto")]
pub(crate) unsafe fn cipher_round(block: &mut Block, round_key: &Block) {
    let b = vld1q_u8(block.as_ptr());
    let k = vld1q_u8(round_key.as_ptr());

    // AES single round encryption (all-zero round key, deferred until the end)
    let mut state = vaeseq_u8(b, vdupq_n_u8(0));

    // AES mix columns (the `vaeseq_u8` instruction otherwise omits this step)
    state = vaesmcq_u8(state);

    // AES add round key (bitwise XOR)
    state = veorq_u8(state, k);

    vst1q_u8(block.as_mut_ptr(), state);
}

/// AES equivalent inverse cipher (decrypt) round function.
#[allow(clippy::cast_ptr_alignment)]
#[target_feature(enable = "crypto")]
pub(crate) unsafe fn equiv_inv_cipher_round(block: &mut Block, round_key: &Block) {
    let b = vld1q_u8(block.as_ptr());
    let k = vld1q_u8(round_key.as_ptr());

    // AES single round decryption (all-zero round key, deferred until the end)
    let mut state = vaesdq_u8(b, vdupq_n_u8(0));

    // AES inverse mix columns (the `vaesdq_u8` instruction otherwise omits this step)
    state = vaesimcq_u8(state);

    // AES add round key (bitwise XOR)
    state = veorq_u8(state, k);

    vst1q_u8(block.as_mut_ptr(), state);
}

/// AES inverse mix columns function.
#[allow(clippy::cast_ptr_alignment)]
#[target_feature(enable = "crypto")]
pub(crate) unsafe fn inv_mix_columns(block: &mut Block) {
    let b = vld1q_u8(block.as_ptr());
    let out = vaesimcq_u8(b);
    vst1q_u8(block.as_mut_ptr(), out);
}
