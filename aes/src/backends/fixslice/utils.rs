use super::{BatchBlocks, State, Word};

/// Replicate a single 16-byte input block across all slots of a `Batch<W>`.
///
/// Used by the key schedules, which conceptually call `bitslice(...)` on the
/// same input block several times to fill the bitsliced state.
pub(super) fn broadcast<W: Word>(block: &[u8]) -> BatchBlocks<W> {
    debug_assert_eq!(block.len(), 16);
    let mut out = BatchBlocks::<W>::default();
    for slot in out.iter_mut() {
        slot.copy_from_slice(block);
    }
    out
}

#[inline]
pub(super) fn delta_swap_1<W: Word>(a: &mut W, shift: u32, mask: W) {
    let t = (*a ^ ((*a) >> shift)) & mask;
    *a ^= t ^ (t << shift);
}

#[inline]
pub(super) fn delta_swap_2<W: Word>(a: &mut W, b: &mut W, shift: u32, mask: W) {
    let t = (*a ^ ((*b) >> shift)) & mask;
    *a ^= t;
    *b ^= t << shift;
}

/// Applies ShiftRows once on an AES state (or key).
#[cfg(any(not(aes_backend_soft = "compact"), feature = "hazmat"))]
#[inline]
pub(super) fn shift_rows_1<W: Word>(state: &mut [W]) {
    debug_assert_eq!(state.len(), 8);
    for x in state.iter_mut() {
        delta_swap_1(x, W::HALF_ROW, W::pack_rows(0x00, 0x03, 0x0f, 0x0c));
        delta_swap_1(x, W::QUARTER_ROW, W::pack_rows(0x00, 0x33, 0x00, 0x33));
    }
}

/// Applies ShiftRows twice on an AES state (or key).
#[inline]
pub(super) fn shift_rows_2<W: Word>(state: &mut [W]) {
    debug_assert_eq!(state.len(), 8);
    for x in state.iter_mut() {
        delta_swap_1(x, W::HALF_ROW, W::pack_rows(0x00, 0x0f, 0x00, 0x0f));
    }
}

/// Applies ShiftRows three times on an AES state (or key).
#[inline]
pub(super) fn shift_rows_3<W: Word>(state: &mut [W]) {
    debug_assert_eq!(state.len(), 8);
    for x in state.iter_mut() {
        delta_swap_1(x, W::HALF_ROW, W::pack_rows(0x00, 0x0c, 0x0f, 0x03));
        delta_swap_1(x, W::QUARTER_ROW, W::pack_rows(0x00, 0x33, 0x00, 0x33));
    }
}

#[inline(always)]
pub(super) fn inv_shift_rows_1<W: Word>(state: &mut [W]) {
    shift_rows_3(state);
}

#[inline(always)]
pub(super) fn inv_shift_rows_2<W: Word>(state: &mut [W]) {
    shift_rows_2(state);
}

#[cfg(not(aes_backend_soft = "compact"))]
#[inline(always)]
pub(super) fn inv_shift_rows_3<W: Word>(state: &mut [W]) {
    shift_rows_1(state);
}

/// XOR the columns after the S-box during the key schedule round function.
///
/// The `idx_xor` parameter refers to the index of the previous round key
/// involved in the XOR computation (should be 8 and 16 for AES-128 and AES-256,
/// respectively).
///
/// The `idx_ror` parameter refers to the rotation value, which varies between the
/// different key schedules.
pub(super) fn xor_columns<W: Word>(rkeys: &mut [W], offset: usize, idx_xor: usize, idx_ror: u32) {
    for i in 0..8 {
        let off_i = offset + i;
        let rk = rkeys[off_i - idx_xor] ^ (W::uniform_row(0x03) & rkeys[off_i].ror(idx_ror));
        rkeys[off_i] = rk
            ^ (W::uniform_row(0xfc) & (rk << W::QUARTER_ROW))
            ^ (W::uniform_row(0xf0) & (rk << W::HALF_ROW))
            ^ (W::uniform_row(0xc0) & (rk << (3 * W::QUARTER_ROW)));
    }
}

/// Copy 32-bytes within the provided slice to an 8-byte offset.
pub(super) fn memshift32<W: Word>(buffer: &mut [W], src_offset: usize) {
    debug_assert_eq!(src_offset % 8, 0);

    let dst_offset = src_offset + 8;
    debug_assert!(dst_offset + 8 <= buffer.len());

    for i in (0..8).rev() {
        buffer[dst_offset + i] = buffer[src_offset + i];
    }
}

/// XOR the round key into the internal state. The round keys are expected
/// to be pre-computed and packed in the fixsliced representation.
#[inline]
pub(super) fn add_round_key<W: Word>(state: &mut State<W>, rkey: &[W]) {
    debug_assert_eq!(rkey.len(), 8);
    for (a, b) in state.iter_mut().zip(rkey) {
        *a ^= *b;
    }
}

#[inline(always)]
pub(super) fn add_round_constant_bit<W: Word>(state: &mut [W], bit: usize) {
    state[bit] ^= W::pack_rows(0x00, 0xc0, 0x00, 0x00);
}
