use crate::armv9::expand::RoundKeys;
use cipher::{array::Array, typenum::U16};

// // TODO(silvanshade): switch to intrinsics when available
// #[rustfmt::skip]
// global_asm! {
//     ".balign 8",
//     ".global aes_armv9_expand_aes128_expand_key",
//     ".type aes_armv9_expand_aes128_expand_key, %function",
//     "aes_armv9_expand_aes128_expand_key:",
// }
// extern "C" {
//     fn aes_armv9_expand_aes128_expand_key(dst: *mut u8, src: *const u8);
// }

#[inline(always)]
pub fn expand_key(key: &Array<u8, U16>) -> RoundKeys<11> {
    unsafe { crate::armv9::expand::expand_key(key.as_ref()) }
}

#[inline(always)]
pub fn inv_expanded_keys(expanded_keys: &mut RoundKeys<11>) {
    unsafe { crate::armv9::expand::inv_expanded_keys(expanded_keys) }
}
