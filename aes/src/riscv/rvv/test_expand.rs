#![allow(clippy::zero_prefixed_literal)]

use super::RoundKeys;
use crate::riscv::test::*;

fn store_expanded_keys<const N: usize>(input: RoundKeys<N>) -> [[u8; 16]; N] {
    let mut output = [[0u8; 16]; N];
    for (src, dst) in input.iter().zip(output.iter_mut()) {
        let b0 = src[0].to_ne_bytes();
        let b1 = src[1].to_ne_bytes();
        let b2 = src[2].to_ne_bytes();
        let b3 = src[3].to_ne_bytes();
        dst[00..04].copy_from_slice(&b0);
        dst[04..08].copy_from_slice(&b1);
        dst[08..12].copy_from_slice(&b2);
        dst[12..16].copy_from_slice(&b3);
    }
    output
}

// NOTE: Unlike RISC-V scalar crypto instructions, RISC-V vector crypto instructions implicitly
// perform key inversion as part of the cipher coding instructions. There are no distinct vector
// instructions for key inversion. Hence, no definition of `inv_expanded_keys` used below.

#[test]
fn aes128_key_expansion() {
    let ek = super::expand::aes128::expand_key(&AES128_KEY);
    assert_eq!(store_expanded_keys(ek), AES128_EXP_KEYS);
}

// NOTE: AES-192 is only implemented if scalar-crypto is enabled.
#[cfg(all(
    target_arch = "riscv64",
    target_feature = "zknd",
    target_feature = "zkne"
))]
#[test]
fn aes192_key_expansion() {
    let ek = super::expand::aes192::expand_key(&AES192_KEY);
    assert_eq!(store_expanded_keys(ek), AES192_EXP_KEYS);
}

#[test]
fn aes256_key_expansion() {
    let ek = super::expand::aes256::expand_key(&AES256_KEY);
    assert_eq!(store_expanded_keys(ek), AES256_EXP_KEYS);
}
