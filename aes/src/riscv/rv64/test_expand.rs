#![allow(clippy::zero_prefixed_literal)]

use crate::riscv::rv64::{
    RoundKey, RoundKeys,
    expand::{KeySchedule, inv_expanded_keys},
};
use crate::riscv::test::*;

fn load_expanded_keys<const N: usize>(input: [[u8; 16]; N]) -> RoundKeys<N> {
    let mut output = [RoundKey::from(<[u64; 2]>::default()); N];
    for (src, dst) in input.iter().zip(output.iter_mut()) {
        let ptr = src.as_ptr().cast::<u64>();
        dst[0] = unsafe { ptr.add(0).read_unaligned() };
        dst[1] = unsafe { ptr.add(1).read_unaligned() };
    }
    output
}

pub(crate) fn store_expanded_keys<const N: usize>(input: RoundKeys<N>) -> [[u8; 16]; N] {
    let mut output = [[0u8; 16]; N];
    for (src, dst) in input.iter().zip(output.iter_mut()) {
        let b0 = src[0].to_ne_bytes();
        let b1 = src[1].to_ne_bytes();
        dst[00..08].copy_from_slice(&b0);
        dst[08..16].copy_from_slice(&b1);
    }
    output
}

#[test]
fn aes128_key_expansion() {
    let ek = KeySchedule::<2, 11>::expand_key(&AES128_KEY);
    assert_eq!(store_expanded_keys(ek), AES128_EXP_KEYS);
}

#[test]
fn aes128_key_expansion_inv() {
    let mut ek = load_expanded_keys(AES128_EXP_KEYS);
    inv_expanded_keys(&mut ek);
    assert_eq!(store_expanded_keys(ek), AES128_EXP_INVKEYS);
}

#[test]
fn aes192_key_expansion() {
    let ek = KeySchedule::<3, 13>::expand_key(&AES192_KEY);
    assert_eq!(store_expanded_keys(ek), AES192_EXP_KEYS);
}

#[test]
fn aes192_key_expansion_inv() {
    let mut ek = load_expanded_keys(AES192_EXP_KEYS);
    inv_expanded_keys(&mut ek);
    assert_eq!(store_expanded_keys(ek), AES192_EXP_INVKEYS);
}

#[test]
fn aes256_key_expansion() {
    let ek = KeySchedule::<4, 15>::expand_key(&AES256_KEY);
    assert_eq!(store_expanded_keys(ek), AES256_EXP_KEYS);
}

#[test]
fn aes256_key_expansion_inv() {
    let mut ek = load_expanded_keys(AES256_EXP_KEYS);
    inv_expanded_keys(&mut ek);
    assert_eq!(store_expanded_keys(ek), AES256_EXP_INVKEYS);
}
