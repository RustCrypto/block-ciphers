use crate::riscv::rv64::{RoundKey, RoundKeys};
use core::arch::riscv64::*;

#[inline]
#[target_feature(enable = "zknd", enable = "zkne")]
pub(crate) fn aes128_expand_key(key: &[u8; 16]) -> RoundKeys<11> {
    let (word_bytes, tail) = key.as_chunks::<8>();
    assert!(tail.is_empty());

    let mut cols: [u64; 2] = core::array::from_fn(|i| u64::from_ne_bytes(word_bytes[i]));
    let mut keys = <[RoundKey; 11]>::default();

    keys[0][0] = cols[0];
    keys[0][1] = cols[1];

    let s = aes64ks1i(cols[1], 0);
    cols[0] = aes64ks2(s, cols[0]);
    cols[1] = aes64ks2(cols[0], cols[1]);

    keys[1][0] = cols[0];
    keys[1][1] = cols[1];

    let s = aes64ks1i(cols[1], 1);
    cols[0] = aes64ks2(s, cols[0]);
    cols[1] = aes64ks2(cols[0], cols[1]);

    keys[2][0] = cols[0];
    keys[2][1] = cols[1];

    let s = aes64ks1i(cols[1], 2);
    cols[0] = aes64ks2(s, cols[0]);
    cols[1] = aes64ks2(cols[0], cols[1]);

    keys[3][0] = cols[0];
    keys[3][1] = cols[1];

    let s = aes64ks1i(cols[1], 3);
    cols[0] = aes64ks2(s, cols[0]);
    cols[1] = aes64ks2(cols[0], cols[1]);

    keys[4][0] = cols[0];
    keys[4][1] = cols[1];

    let s = aes64ks1i(cols[1], 4);
    cols[0] = aes64ks2(s, cols[0]);
    cols[1] = aes64ks2(cols[0], cols[1]);

    keys[5][0] = cols[0];
    keys[5][1] = cols[1];

    let s = aes64ks1i(cols[1], 5);
    cols[0] = aes64ks2(s, cols[0]);
    cols[1] = aes64ks2(cols[0], cols[1]);

    keys[6][0] = cols[0];
    keys[6][1] = cols[1];

    let s = aes64ks1i(cols[1], 6);
    cols[0] = aes64ks2(s, cols[0]);
    cols[1] = aes64ks2(cols[0], cols[1]);

    keys[7][0] = cols[0];
    keys[7][1] = cols[1];

    let s = aes64ks1i(cols[1], 7);
    cols[0] = aes64ks2(s, cols[0]);
    cols[1] = aes64ks2(cols[0], cols[1]);

    keys[8][0] = cols[0];
    keys[8][1] = cols[1];

    let s = aes64ks1i(cols[1], 8);
    cols[0] = aes64ks2(s, cols[0]);
    cols[1] = aes64ks2(cols[0], cols[1]);

    keys[9][0] = cols[0];
    keys[9][1] = cols[1];

    let s = aes64ks1i(cols[1], 9);
    cols[0] = aes64ks2(s, cols[0]);
    cols[1] = aes64ks2(cols[0], cols[1]);

    keys[10][0] = cols[0];
    keys[10][1] = cols[1];

    keys
}

#[inline]
#[target_feature(enable = "zknd", enable = "zkne")]
pub(crate) fn aes192_expand_key(ckey: &[u8; 24]) -> RoundKeys<13> {
    let (word_bytes, tail) = ckey.as_chunks::<8>();
    assert!(tail.is_empty());

    let mut cols: [u64; 3] = core::array::from_fn(|i| u64::from_ne_bytes(word_bytes[i]));
    let mut keys = <[RoundKey; 13]>::default();

    keys[0][0] = cols[0];
    keys[0][1] = cols[1];
    keys[1][0] = cols[2];

    let s = aes64ks1i(cols[2], 0);
    cols[0] = aes64ks2(s, cols[0]);
    cols[1] = aes64ks2(cols[0], cols[1]);
    cols[2] = aes64ks2(cols[1], cols[2]);

    keys[1][1] = cols[0];
    keys[2][0] = cols[1];
    keys[2][1] = cols[2];

    let s = aes64ks1i(cols[2], 1);
    cols[0] = aes64ks2(s, cols[0]);
    cols[1] = aes64ks2(cols[0], cols[1]);
    cols[2] = aes64ks2(cols[1], cols[2]);

    keys[3][0] = cols[0];
    keys[3][1] = cols[1];
    keys[4][0] = cols[2];

    let s = aes64ks1i(cols[2], 2);
    cols[0] = aes64ks2(s, cols[0]);
    cols[1] = aes64ks2(cols[0], cols[1]);
    cols[2] = aes64ks2(cols[1], cols[2]);

    keys[4][1] = cols[0];
    keys[5][0] = cols[1];
    keys[5][1] = cols[2];

    let s = aes64ks1i(cols[2], 3);
    cols[0] = aes64ks2(s, cols[0]);
    cols[1] = aes64ks2(cols[0], cols[1]);
    cols[2] = aes64ks2(cols[1], cols[2]);

    keys[6][0] = cols[0];
    keys[6][1] = cols[1];
    keys[7][0] = cols[2];

    let s = aes64ks1i(cols[2], 4);
    cols[0] = aes64ks2(s, cols[0]);
    cols[1] = aes64ks2(cols[0], cols[1]);
    cols[2] = aes64ks2(cols[1], cols[2]);

    keys[7][1] = cols[0];
    keys[8][0] = cols[1];
    keys[8][1] = cols[2];

    let s = aes64ks1i(cols[2], 5);
    cols[0] = aes64ks2(s, cols[0]);
    cols[1] = aes64ks2(cols[0], cols[1]);
    cols[2] = aes64ks2(cols[1], cols[2]);

    keys[9][0] = cols[0];
    keys[9][1] = cols[1];
    keys[10][0] = cols[2];

    let s = aes64ks1i(cols[2], 6);
    cols[0] = aes64ks2(s, cols[0]);
    cols[1] = aes64ks2(cols[0], cols[1]);
    cols[2] = aes64ks2(cols[1], cols[2]);

    keys[10][1] = cols[0];
    keys[11][0] = cols[1];
    keys[11][1] = cols[2];

    let s = aes64ks1i(cols[2], 7);
    cols[0] = aes64ks2(s, cols[0]);
    cols[1] = aes64ks2(cols[0], cols[1]);

    keys[12][0] = cols[0];
    keys[12][1] = cols[1];

    keys
}

#[inline]
#[target_feature(enable = "zknd", enable = "zkne")]
pub(crate) fn aes256_expand_key(user_key: &[u8; 32]) -> RoundKeys<15> {
    let (word_bytes, tail) = user_key.as_chunks::<8>();
    assert!(tail.is_empty());

    let mut cols: [u64; 4] = core::array::from_fn(|i| u64::from_ne_bytes(word_bytes[i]));
    let mut keys = <[RoundKey; 15]>::default();

    keys[0][0] = cols[0];
    keys[0][1] = cols[1];
    keys[1][0] = cols[2];
    keys[1][1] = cols[3];

    let s = aes64ks1i(cols[3], 0);
    cols[0] = aes64ks2(s, cols[0]);
    cols[1] = aes64ks2(cols[0], cols[1]);
    let s = aes64ks1i(cols[1], 0xA);
    cols[2] = aes64ks2(s, cols[2]);
    cols[3] = aes64ks2(cols[2], cols[3]);

    keys[2][0] = cols[0];
    keys[2][1] = cols[1];
    keys[3][0] = cols[2];
    keys[3][1] = cols[3];

    let s = aes64ks1i(cols[3], 1);
    cols[0] = aes64ks2(s, cols[0]);
    cols[1] = aes64ks2(cols[0], cols[1]);
    let s = aes64ks1i(cols[1], 0xA);
    cols[2] = aes64ks2(s, cols[2]);
    cols[3] = aes64ks2(cols[2], cols[3]);

    keys[4][0] = cols[0];
    keys[4][1] = cols[1];
    keys[5][0] = cols[2];
    keys[5][1] = cols[3];

    let s = aes64ks1i(cols[3], 2);
    cols[0] = aes64ks2(s, cols[0]);
    cols[1] = aes64ks2(cols[0], cols[1]);
    let s = aes64ks1i(cols[1], 0xA);
    cols[2] = aes64ks2(s, cols[2]);
    cols[3] = aes64ks2(cols[2], cols[3]);

    keys[6][0] = cols[0];
    keys[6][1] = cols[1];
    keys[7][0] = cols[2];
    keys[7][1] = cols[3];

    let s = aes64ks1i(cols[3], 3);
    cols[0] = aes64ks2(s, cols[0]);
    cols[1] = aes64ks2(cols[0], cols[1]);
    let s = aes64ks1i(cols[1], 0xA);
    cols[2] = aes64ks2(s, cols[2]);
    cols[3] = aes64ks2(cols[2], cols[3]);

    keys[8][0] = cols[0];
    keys[8][1] = cols[1];
    keys[9][0] = cols[2];
    keys[9][1] = cols[3];

    let s = aes64ks1i(cols[3], 4);
    cols[0] = aes64ks2(s, cols[0]);
    cols[1] = aes64ks2(cols[0], cols[1]);
    let s = aes64ks1i(cols[1], 0xA);
    cols[2] = aes64ks2(s, cols[2]);
    cols[3] = aes64ks2(cols[2], cols[3]);

    keys[10][0] = cols[0];
    keys[10][1] = cols[1];
    keys[11][0] = cols[2];
    keys[11][1] = cols[3];

    let s = aes64ks1i(cols[3], 5);
    cols[0] = aes64ks2(s, cols[0]);
    cols[1] = aes64ks2(cols[0], cols[1]);
    let s = aes64ks1i(cols[1], 0xA);
    cols[2] = aes64ks2(s, cols[2]);
    cols[3] = aes64ks2(cols[2], cols[3]);

    keys[12][0] = cols[0];
    keys[12][1] = cols[1];
    keys[13][0] = cols[2];
    keys[13][1] = cols[3];

    let s = aes64ks1i(cols[3], 6);
    cols[0] = aes64ks2(s, cols[0]);
    cols[1] = aes64ks2(cols[0], cols[1]);

    keys[14][0] = cols[0];
    keys[14][1] = cols[1];

    keys
}

#[inline]
#[target_feature(enable = "zknd", enable = "zkne")]
pub fn inv_expanded_keys<const N: usize>(keys: &mut RoundKeys<N>) {
    (1..N - 1).for_each(|i| {
        keys[i][0] = aes64im(keys[i][0]);
        keys[i][1] = aes64im(keys[i][1]);
    });
}
