//! Raw AES round function: AES-NI support.
//!
//! Note: this isn't actually used in the `Aes128`/`Aes192`/`Aes256`
//! implementations in this crate, but instead provides raw AES-NI accelerated
//! access to the AES round function gated under the `hazmat` crate feature.

use super::arch::*;
use crate::Block;

/// AES cipher (encrypt) round function.
#[allow(clippy::cast_ptr_alignment)]
#[target_feature(enable = "aes")]
pub(crate) unsafe fn cipher(block: &mut Block, round_key: &Block) {
    // Safety: `loadu` and `storeu` support unaligned access
    let b = _mm_loadu_si128(block.as_ptr() as *const __m128i);
    let k = _mm_loadu_si128(round_key.as_ptr() as *const __m128i);
    let out = _mm_aesenc_si128(b, k);
    _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, out);
}

/// AES cipher (encrypt) round function.
#[allow(clippy::cast_ptr_alignment)]
#[target_feature(enable = "aes")]
pub(crate) unsafe fn equiv_inv_cipher(block: &mut Block, round_key: &Block) {
    // Safety: `loadu` and `storeu` support unaligned access
    let b = _mm_loadu_si128(block.as_ptr() as *const __m128i);
    let k = _mm_loadu_si128(round_key.as_ptr() as *const __m128i);
    let out = _mm_aesdec_si128(b, k);
    _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, out);
}
