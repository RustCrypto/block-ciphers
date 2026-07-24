use super::RoundKeys;
use crate::Block;
use cipher::{Array, array::ArraySize, consts::U2, inout::InOut, typenum::Quot};
use core::ops::Div;

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

pub(super) type RoundKeys2<const ROUNDS: usize> = [__m256i; ROUNDS];

type SimdBlocks<ParBlocks> = Array<__m256i, Quot<ParBlocks, U2>>;

#[inline]
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn broadcast_keys<const RK: usize>(keys: &RoundKeys<RK>) -> RoundKeys2<RK> {
    keys.map(|key| _mm256_broadcastsi128_si256(key))
}

#[inline]
#[target_feature(enable = "vaes")]
pub(crate) unsafe fn encrypt_par<const RK: usize, ParBlocks>(
    keys: &RoundKeys2<RK>,
    mut blocks: InOut<'_, '_, Array<Block, ParBlocks>>,
) where
    ParBlocks: ArraySize + Div<U2>,
    Quot<ParBlocks, U2>: ArraySize,
{
    const {
        assert!(matches!(RK, 11 | 13 | 15));
        assert!(ParBlocks::USIZE % 2 == 0);
    }

    let mut blocks2 = load(blocks.get_in());

    for block2 in &mut blocks2 {
        *block2 = _mm256_xor_si256(*block2, keys[0]);
    }
    for key in &keys[1..RK - 1] {
        for block2 in &mut blocks2 {
            *block2 = _mm256_aesenc_epi128(*block2, *key);
        }
    }
    for block2 in &mut blocks2 {
        *block2 = _mm256_aesenclast_epi128(*block2, keys[RK - 1]);
    }

    store(blocks.get_out(), blocks2);
}

#[inline]
#[target_feature(enable = "vaes")]
pub(crate) unsafe fn decrypt_par<const RK: usize, ParBlocks>(
    keys: &RoundKeys2<RK>,
    mut blocks: InOut<'_, '_, Array<Block, ParBlocks>>,
) where
    ParBlocks: ArraySize + Div<U2>,
    Quot<ParBlocks, U2>: ArraySize,
{
    const {
        assert!(matches!(RK, 11 | 13 | 15));
        assert!(ParBlocks::USIZE % 2 == 0);
    }

    let mut blocks2 = load(blocks.get_in());

    for block2 in &mut blocks2 {
        *block2 = _mm256_xor_si256(*block2, keys[0]);
    }
    for key in &keys[1..RK - 1] {
        for block2 in &mut blocks2 {
            *block2 = _mm256_aesdec_epi128(*block2, *key);
        }
    }
    for block2 in &mut blocks2 {
        *block2 = _mm256_aesdeclast_epi128(*block2, keys[RK - 1]);
    }

    store(blocks.get_out(), blocks2);
}

#[inline]
#[target_feature(enable = "avx")]
fn load<ParBlocks>(blocks: &Array<Block, ParBlocks>) -> SimdBlocks<ParBlocks>
where
    ParBlocks: ArraySize + Div<U2>,
    Quot<ParBlocks, U2>: ArraySize,
{
    const { assert!(ParBlocks::USIZE % 2 == 0) }

    let in_ptr: *const __m256i = blocks.as_ptr().cast();
    Array::from_fn(|i| unsafe { _mm256_loadu_si256(in_ptr.add(i)) })
}

#[inline]
#[target_feature(enable = "avx")]
fn store<ParBlocks>(dst: &mut Array<Block, ParBlocks>, blocks: SimdBlocks<ParBlocks>)
where
    ParBlocks: ArraySize + Div<U2>,
    Quot<ParBlocks, U2>: ArraySize,
{
    const { assert!(ParBlocks::USIZE % 2 == 0) }

    let out_ptr: *mut __m256i = dst.as_mut_ptr().cast();
    for (i, block) in blocks.into_iter().enumerate() {
        unsafe { _mm256_storeu_si256(out_ptr.add(i), block) }
    }
}
