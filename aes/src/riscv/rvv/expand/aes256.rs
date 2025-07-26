use crate::riscv::rvv::expand::{RoundKey, RoundKeys};
use core::{arch::global_asm, mem::MaybeUninit};

// TODO(silvanshade): switch to intrinsics when available
#[rustfmt::skip]
global_asm! {
    // INPUTS:
    //      a0:  uint8_t exp[240]
    //      a1: uint32_t key[8]
    // SAFETY:
    //      - a0 must be valid pointers to memory regions of at least 240 bytes
    //      - a1 must be valid pointers to memory regions of at least  32 bytes
    //      - on exit: a0 is overwritten with expanded round keys
    //      - on exit: a1 is unchanged
    ".attribute arch, \"rv64gcv1p0_zvkned1p0\"",
    ".balign 4",
    ".global aes_riscv_rv64_vector_expand_aes256_expand_key",
    ".type aes_riscv_rv64_vector_expand_aes256_expand_key, @function",
    "aes_riscv_rv64_vector_expand_aes256_expand_key:",
        "vsetivli zero, 4, e32, m4, ta, ma",                            // configure RVV for vector shape: 4 x 32b x 1

        "vle32.v v4, (a1)",                                             // load 1st 16-bytes of user-key [128:000]
        "addi a1, a1, 16",
        "vle32.v v8, (a1)",                                             // load 2nd 16-bytes of user-key [256:128]

        "vse32.v v4, (a0)", "addi a0, a0, 16",                          // save round 00 key (user-key [128:000])
        "vse32.v v8, (a0)", "addi a0, a0, 16",                          // save round 01 key (user-key [256:128])

        "vaeskf2.vi v4, v8,  2", "vse32.v v4, (a0)", "addi a0, a0, 16", // expand and save round 02 key
        "vaeskf2.vi v8, v4,  3", "vse32.v v8, (a0)", "addi a0, a0, 16", // expand and save round 03 key

        "vaeskf2.vi v4, v8,  4", "vse32.v v4, (a0)", "addi a0, a0, 16", // expand and save round 04 key
        "vaeskf2.vi v8, v4,  5", "vse32.v v8, (a0)", "addi a0, a0, 16", // expand and save round 05 key

        "vaeskf2.vi v4, v8,  6", "vse32.v v4, (a0)", "addi a0, a0, 16", // expand and save round 06 key
        "vaeskf2.vi v8, v4,  7", "vse32.v v8, (a0)", "addi a0, a0, 16", // expand and save round 07 key

        "vaeskf2.vi v4, v8,  8", "vse32.v v4, (a0)", "addi a0, a0, 16", // expand and save round 08 key
        "vaeskf2.vi v8, v4,  9", "vse32.v v8, (a0)", "addi a0, a0, 16", // expand and save round 09 key

        "vaeskf2.vi v4, v8, 10", "vse32.v v4, (a0)", "addi a0, a0, 16", // expand and save round 10 key
        "vaeskf2.vi v8, v4, 11", "vse32.v v8, (a0)", "addi a0, a0, 16", // expand and save round 11 key

        "vaeskf2.vi v4, v8, 12", "vse32.v v4, (a0)", "addi a0, a0, 16", // expand and save round 12 key
        "vaeskf2.vi v8, v4, 13", "vse32.v v8, (a0)", "addi a0, a0, 16", // expand and save round 13 key

        "vaeskf2.vi v4, v8, 14", "vse32.v v4, (a0)",                    // expand and save round 14 key

        "ret",
}
unsafe extern "C" {
    fn aes_riscv_rv64_vector_expand_aes256_expand_key(dst: *mut u32, src: *const u8);
}

#[inline(always)]
pub fn expand_key(key: &[u8; 32]) -> RoundKeys<15> {
    let mut exp: [MaybeUninit<RoundKey>; 15] = unsafe { MaybeUninit::uninit().assume_init() };
    unsafe {
        let exp = exp.as_mut_ptr().cast::<u32>();
        let key = key.as_ptr();
        aes_riscv_rv64_vector_expand_aes256_expand_key(exp, key);
    };
    // SAFETY: All positions have been initialized.
    let out: RoundKeys<15> = unsafe { ::core::mem::transmute(exp) };
    out
}
