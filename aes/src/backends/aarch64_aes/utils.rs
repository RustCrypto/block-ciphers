use crate::Block;
use core::arch::aarch64::{uint8x16_t, vld1q_u8, vst1q_u8};

#[target_feature(enable = "neon")]
pub(super) fn load_block(block: &Block) -> uint8x16_t {
    // SAFETY: `vld1q_u8` supports unaligned loads
    unsafe { vld1q_u8(block.as_ptr()) }
}

#[target_feature(enable = "neon")]
pub(super) fn store_block(dst: &mut Block, block: uint8x16_t) {
    // SAFETY: `vst1q_u8` supports unaligned stores
    unsafe { vst1q_u8(dst.as_mut_ptr(), block) }
}
