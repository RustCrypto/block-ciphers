//! ARMv8 extension intrinsics

#![allow(unsafe_code)]

use core::arch::{aarch64::*, asm};

#[inline]
#[target_feature(enable = "sm4")]
pub(super) unsafe fn vsm4eq_u32(mut a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
    asm!(
        "SM4E {d:v}.4S, {n:v}.4S",
        d = inout(vreg) a,
        n = in(vreg) b,
        options(pure, nomem, nostack, preserves_flags)
    );
    a
}

#[inline]
#[target_feature(enable = "sm4")]
pub(super) unsafe fn vsm4ekeyq_u32(a: uint32x4_t, b: uint32x4_t) -> uint32x4_t {
    let mut key: uint32x4_t;
    asm!(
        "SM4EKEY {d:v}.4S, {n:v}.4S, {m:v}.4S",
        d = out(vreg) key,
        n = in(vreg) a,
        m = in(vreg) b,
        options(pure, nomem, nostack, preserves_flags)
    );
    key
}
