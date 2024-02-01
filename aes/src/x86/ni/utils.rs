//! Utility functions

// TODO(tarcieri): check performance impact / generated assembly changes
#![allow(clippy::needless_range_loop)]

use super::arch::*;
use crate::{Block, Block8};

pub type U128x8 = [__m128i; 8];

#[cfg(test)]
pub(crate) fn check(a: &[__m128i], b: &[[u64; 2]]) {
    for (v1, v2) in a.iter().zip(b) {
        let t1: [u64; 2] = unsafe { core::mem::transmute(*v1) };
        let t2 = [v2[0].to_be(), v2[1].to_be()];
        assert_eq!(t1, t2);
    }
}

#[inline(always)]
pub(crate) fn load8(blocks: *const Block8) -> U128x8 {
    unsafe {
        let p = blocks.cast::<Block>();
        [
            _mm_loadu_si128(p.add(0).cast()),
            _mm_loadu_si128(p.add(1).cast()),
            _mm_loadu_si128(p.add(2).cast()),
            _mm_loadu_si128(p.add(3).cast()),
            _mm_loadu_si128(p.add(4).cast()),
            _mm_loadu_si128(p.add(5).cast()),
            _mm_loadu_si128(p.add(6).cast()),
            _mm_loadu_si128(p.add(7).cast()),
        ]
    }
}

#[inline(always)]
pub(crate) fn store8(blocks: *mut Block8, b: U128x8) {
    unsafe {
        let p = blocks.cast::<Block>();
        _mm_storeu_si128(p.add(0).cast(), b[0]);
        _mm_storeu_si128(p.add(1).cast(), b[1]);
        _mm_storeu_si128(p.add(2).cast(), b[2]);
        _mm_storeu_si128(p.add(3).cast(), b[3]);
        _mm_storeu_si128(p.add(4).cast(), b[4]);
        _mm_storeu_si128(p.add(5).cast(), b[5]);
        _mm_storeu_si128(p.add(6).cast(), b[6]);
        _mm_storeu_si128(p.add(7).cast(), b[7]);
    }
}

#[inline(always)]
pub(crate) fn xor8(b: &mut U128x8, key: __m128i) {
    unsafe {
        b[0] = _mm_xor_si128(b[0], key);
        b[1] = _mm_xor_si128(b[1], key);
        b[2] = _mm_xor_si128(b[2], key);
        b[3] = _mm_xor_si128(b[3], key);
        b[4] = _mm_xor_si128(b[4], key);
        b[5] = _mm_xor_si128(b[5], key);
        b[6] = _mm_xor_si128(b[6], key);
        b[7] = _mm_xor_si128(b[7], key);
    }
}

#[inline(always)]
pub(crate) fn aesenc8(buffer: &mut U128x8, key: __m128i) {
    for i in 0..8 {
        buffer[i] = unsafe { _mm_aesenc_si128(buffer[i], key) };
    }
}

#[inline(always)]
pub(crate) fn aesenclast8(buffer: &mut U128x8, key: __m128i) {
    for i in 0..8 {
        buffer[i] = unsafe { _mm_aesenclast_si128(buffer[i], key) };
    }
}

#[inline(always)]
pub(crate) fn aesdec8(buffer: &mut U128x8, key: __m128i) {
    for i in 0..8 {
        buffer[i] = unsafe { _mm_aesdec_si128(buffer[i], key) };
    }
}

#[inline(always)]
pub(crate) fn aesdeclast8(buffer: &mut U128x8, key: __m128i) {
    for i in 0..8 {
        buffer[i] = unsafe { _mm_aesdeclast_si128(buffer[i], key) };
    }
}
