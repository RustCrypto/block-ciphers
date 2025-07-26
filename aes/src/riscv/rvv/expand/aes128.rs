use super::{RoundKey, RoundKeys};
use core::{arch::global_asm, mem::MaybeUninit};

// TODO(silvanshade): switch to intrinsics when available
#[rustfmt::skip]
    global_asm! {
        // INPUTS:
        //      a0:  uint8_t exp[176]
        //      a1: uint32_t key[4]
        // SAFETY:
        //      - a0 must be valid pointers to memory regions of at least 176 bytes
        //      - a1 must be valid pointers to memory regions of at least  16 bytes
        //      - on exit: a0 is overwritten with expanded round keys
        //      - on exit: a1 is unchanged
        ".attribute arch, \"rv64gcv1p0_zvkned1p0\"",
        ".balign 4",
        ".global aes_riscv_rv64_vector_expand_aes128_expand_key",
        ".type aes_riscv_rv64_vector_expand_aes128_expand_key, @function",
        "aes_riscv_rv64_vector_expand_aes128_expand_key:",
            "vsetivli zero, 4, e32, m1, ta, ma",                            // configure RVV for vector shape: 4 x 32b x 1

            "vle32.v v4, (a1)",                                             // load user-key
            "vse32.v v4, (a0)",                                             //            save round 00 key (user-key)

            "vaeskf1.vi v4, v4,  1", "addi a0, a0, 16", "vse32.v v4, (a0)", // expand and save round 01 key
            "vaeskf1.vi v4, v4,  2", "addi a0, a0, 16", "vse32.v v4, (a0)", // expand and save round 02 key
            "vaeskf1.vi v4, v4,  3", "addi a0, a0, 16", "vse32.v v4, (a0)", // expand and save round 03 key
            "vaeskf1.vi v4, v4,  4", "addi a0, a0, 16", "vse32.v v4, (a0)", // expand and save round 04 key
            "vaeskf1.vi v4, v4,  5", "addi a0, a0, 16", "vse32.v v4, (a0)", // expand and save round 05 key
            "vaeskf1.vi v4, v4,  6", "addi a0, a0, 16", "vse32.v v4, (a0)", // expand and save round 06 key
            "vaeskf1.vi v4, v4,  7", "addi a0, a0, 16", "vse32.v v4, (a0)", // expand and save round 07 key
            "vaeskf1.vi v4, v4,  8", "addi a0, a0, 16", "vse32.v v4, (a0)", // expand and save round 08 key
            "vaeskf1.vi v4, v4,  9", "addi a0, a0, 16", "vse32.v v4, (a0)", // expand and save round 09 key
            "vaeskf1.vi v4, v4, 10", "addi a0, a0, 16", "vse32.v v4, (a0)", // expand and save round 10 key

            "ret",
    }
unsafe extern "C" {
    fn aes_riscv_rv64_vector_expand_aes128_expand_key(dst: *mut u32, src: *const u8);
}

#[inline(always)]
pub fn expand_key(key: &[u8; 16]) -> RoundKeys<11> {
    let mut exp: [MaybeUninit<RoundKey>; 11] = unsafe { MaybeUninit::uninit().assume_init() };
    unsafe {
        let exp = exp.as_mut_ptr().cast::<u32>();
        let key = key.as_ptr();
        aes_riscv_rv64_vector_expand_aes128_expand_key(exp, key);
    };
    // SAFETY: All positions have been initialized.
    let out: RoundKeys<11> = unsafe { ::core::mem::transmute(exp) };
    out
}
