//! Low-level "hazmat" AES functions: ARMv8 Cryptography Extensions support.
//!
//! Note: this isn't actually used in the `Aes128`/`Aes192`/`Aes256`
//! implementations in this crate, but instead provides raw accelerated
//! access to the AES round function gated under the `hazmat` crate feature.
use super::utils::{load_block, store_block};
use crate::hazmat::{Block, Block8};
use core::arch::aarch64::*;

/// AES cipher (encrypt) round function.
#[target_feature(enable = "aes")]
pub(crate) fn cipher_round(block: &mut Block, round_key: &Block) {
    let mut b = load_block(block);
    let k = load_block(round_key);

    // AES single round encryption (all-zero round key, deferred until the end)
    b = vaeseq_u8(b, vdupq_n_u8(0));

    // AES mix columns (the `vaeseq_u8` instruction otherwise omits this step)
    b = vaesmcq_u8(b);

    // AES add round key (bitwise XOR)
    b = veorq_u8(b, k);

    store_block(block, b);
}

/// AES cipher (encrypt) round function: parallel version.
#[target_feature(enable = "aes")]
pub(crate) fn cipher_round_par(blocks: &mut Block8, round_keys: &Block8) {
    for i in 0..8 {
        let mut b = load_block(&blocks[i]);

        // AES single round encryption
        b = vaeseq_u8(b, vdupq_n_u8(0));

        // AES mix columns
        b = vaesmcq_u8(b);

        // AES add round key (bitwise XOR)
        let rk = load_block(&round_keys[i]);
        b = veorq_u8(b, rk);

        store_block(&mut blocks[i], b);
    }
}

/// AES equivalent inverse cipher (decrypt) round function.
#[target_feature(enable = "aes")]
pub(crate) fn equiv_inv_cipher_round(block: &mut Block, round_key: &Block) {
    let mut b = load_block(block);
    let k = load_block(round_key);

    // AES single round decryption (all-zero round key, deferred until the end)
    b = vaesdq_u8(b, vdupq_n_u8(0));

    // AES inverse mix columns (the `vaesdq_u8` instruction otherwise omits this step)
    b = vaesimcq_u8(b);

    // AES add round key (bitwise XOR)
    b = veorq_u8(b, k);

    store_block(block, b);
}

/// AES equivalent inverse cipher (decrypt) round function: parallel version.
#[target_feature(enable = "aes")]
pub(crate) fn equiv_inv_cipher_round_par(blocks: &mut Block8, round_keys: &Block8) {
    for i in 0..8 {
        let mut b = load_block(&blocks[i]);

        // AES single round decryption (all-zero round key, deferred until the end)
        b = vaesdq_u8(b, vdupq_n_u8(0));

        // AES inverse mix columns (the `vaesdq_u8` instruction otherwise omits this step)
        b = vaesimcq_u8(b);

        // AES add round key (bitwise XOR)
        let rk = load_block(&round_keys[i]);
        b = veorq_u8(b, rk);

        store_block(&mut blocks[i], b);
    }
}

/// AES mix columns function.
#[target_feature(enable = "aes")]
pub(crate) fn mix_columns(block: &mut Block) {
    let b = load_block(block);
    let out = vaesmcq_u8(b);
    store_block(block, out);
}

/// AES inverse mix columns function.
#[target_feature(enable = "aes")]
pub(crate) fn inv_mix_columns(block: &mut Block) {
    let b = load_block(block);
    let out = vaesimcq_u8(b);
    store_block(block, out);
}
