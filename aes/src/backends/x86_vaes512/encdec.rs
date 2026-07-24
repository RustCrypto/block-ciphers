use super::RoundKeys;
use crate::Block;
use cipher::{Array, array::ArraySize, consts::U4, inout::InOut, typenum::Quot};
use core::ops::Div;

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

pub(super) type RoundKeys4<const ROUNDS: usize> = [__m512i; ROUNDS];

type SimdBlocks<ParBlocks> = Array<__m512i, Quot<ParBlocks, U4>>;

#[inline]
#[target_feature(enable = "avx512f")]
pub(crate) unsafe fn broadcast_keys<const RK: usize>(keys: &RoundKeys<RK>) -> RoundKeys4<RK> {
    keys.map(|key| _mm512_broadcast_i32x4(key))
}

#[inline]
#[target_feature(enable = "avx512f,vaes")]
pub(crate) unsafe fn encrypt_par<const RK: usize, ParBlocks>(
    keys: &RoundKeys4<RK>,
    mut blocks: InOut<'_, '_, Array<Block, ParBlocks>>,
) where
    ParBlocks: ArraySize + Div<U4>,
    Quot<ParBlocks, U4>: ArraySize,
{
    const {
        assert!(matches!(RK, 11 | 13 | 15));
        assert!(ParBlocks::USIZE % 4 == 0);
    }

    let mut blocks4 = load(blocks.get_in());

    for block4 in &mut blocks4 {
        *block4 = _mm512_xor_si512(*block4, keys[0]);
    }
    for key in &keys[1..RK - 1] {
        for block4 in &mut blocks4 {
            *block4 = _mm512_aesenc_epi128(*block4, *key);
        }
    }
    for block4 in &mut blocks4 {
        *block4 = _mm512_aesenclast_epi128(*block4, keys[RK - 1]);
    }

    store(blocks.get_out(), blocks4);
}

#[inline]
#[target_feature(enable = "avx512f,vaes")]
pub(crate) unsafe fn decrypt_par<const RK: usize, ParBlocks>(
    keys: &RoundKeys4<RK>,
    mut blocks: InOut<'_, '_, Array<Block, ParBlocks>>,
) where
    ParBlocks: ArraySize + Div<U4>,
    Quot<ParBlocks, U4>: ArraySize,
{
    const {
        assert!(matches!(RK, 11 | 13 | 15));
        assert!(ParBlocks::USIZE % 4 == 0);
    }

    let mut blocks4 = load(blocks.get_in());

    for block4 in &mut blocks4 {
        *block4 = _mm512_xor_si512(*block4, keys[0]);
    }
    for key in &keys[1..RK - 1] {
        for block4 in &mut blocks4 {
            *block4 = _mm512_aesdec_epi128(*block4, *key);
        }
    }
    for block4 in &mut blocks4 {
        *block4 = _mm512_aesdeclast_epi128(*block4, keys[RK - 1]);
    }

    store(blocks.get_out(), blocks4);
}

#[inline]
#[target_feature(enable = "avx512f")]
fn load<ParBlocks>(blocks: &Array<Block, ParBlocks>) -> SimdBlocks<ParBlocks>
where
    ParBlocks: ArraySize + Div<U4>,
    Quot<ParBlocks, U4>: ArraySize,
{
    const { assert!(ParBlocks::USIZE % 4 == 0) }

    let in_ptr: *const __m512i = blocks.as_ptr().cast();
    Array::from_fn(|i| unsafe { _mm512_loadu_si512(in_ptr.add(i)) })
}

#[inline]
#[target_feature(enable = "avx512f")]
fn store<ParBlocks>(dst: &mut Array<Block, ParBlocks>, blocks: SimdBlocks<ParBlocks>)
where
    ParBlocks: ArraySize + Div<U4>,
    Quot<ParBlocks, U4>: ArraySize,
{
    const { assert!(ParBlocks::USIZE % 4 == 0) }

    let out_ptr: *mut __m512i = dst.as_mut_ptr().cast();
    for (i, block) in blocks.into_iter().enumerate() {
        unsafe { _mm512_storeu_si512(out_ptr.add(i), block) }
    }
}
