use super::RoundKeys;
use core::mem::transmute;

#[inline(always)]
pub fn expand_key(key: &[u8; 24]) -> RoundKeys<13> {
    let output = crate::riscv::rv64::expand::KeySchedule::<3, 13>::expand_key(key);
    // SAFETY: Size is same and [u32] layout is downcast aligned for [u64].
    unsafe { transmute(output) }
}
