use crate::Block;
use cipher::{Array, array::ArraySize};

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[target_feature(enable = "sse2")]
pub(super) fn load_block(block: &Block) -> __m128i {
    let p: *const __m128i = block.as_ptr().cast();
    // SAFETY: sizes of `Block` and `__m128i` are equal and we use unaligned load instruction
    unsafe { _mm_loadu_si128(p) }
}

#[target_feature(enable = "sse2")]
pub(super) fn store_block(dst: &mut Block, block: __m128i) {
    let p: *mut __m128i = dst.as_mut_ptr().cast();
    // SAFETY: sizes of `Block` and `__m128i` are equal and we use unaligned store instruction
    unsafe { _mm_storeu_si128(p, block) }
}

#[target_feature(enable = "sse2")]
pub(super) fn load_batch_blocks<N: ArraySize>(blocks: &Array<Block, N>) -> Array<__m128i, N> {
    Array::from_fn(|i| load_block(&blocks[i]))
}

#[target_feature(enable = "sse2")]
pub(super) fn store_batch_blocks<N: ArraySize>(
    dst: &mut Array<Block, N>,
    blocks: Array<__m128i, N>,
) {
    for i in 0..N::USIZE {
        store_block(&mut dst[i], blocks[i]);
    }
}
