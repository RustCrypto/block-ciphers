use crate::primitives::{ror, swapmovesingle};

#[inline]
pub(crate) fn rearrange_rkey_0(x: &u32) -> u32 {
    let mut tmp = *x;
    swapmovesingle(&mut tmp, 0x00550055, 9);
    swapmovesingle(&mut tmp, 0x000f000f, 12);
    swapmovesingle(&mut tmp, 0x00003333, 18);
    swapmovesingle(&mut tmp, 0x000000ff, 24);
    tmp
}

#[inline]
pub(crate) fn rearrange_rkey_1(x: &u32) -> u32 {
    let mut tmp = *x;
    swapmovesingle(&mut tmp, 0x11111111, 3);
    swapmovesingle(&mut tmp, 0x03030303, 6);
    swapmovesingle(&mut tmp, 0x000f000f, 12);
    swapmovesingle(&mut tmp, 0x000000ff, 24);
    tmp
}

#[inline]
pub(crate) fn rearrange_rkey_2(x: &u32) -> u32 {
    let mut tmp = *x;
    swapmovesingle(&mut tmp, 0x0000aaaa, 15);
    swapmovesingle(&mut tmp, 0x00003333, 18);
    swapmovesingle(&mut tmp, 0x0000f0f0, 12);
    swapmovesingle(&mut tmp, 0x000000ff, 24);
    tmp
}

#[inline]
pub(crate) fn rearrange_rkey_3(x: &u32) -> u32 {
    let mut tmp = *x;
    swapmovesingle(&mut tmp, 0x0a0a0a0a, 3);
    swapmovesingle(&mut tmp, 0x00cc00cc, 6);
    swapmovesingle(&mut tmp, 0x0000f0f0, 12);
    swapmovesingle(&mut tmp, 0x000000ff, 24);
    tmp
}

#[inline]
pub(crate) fn key_update(x: &u32) -> u32 {
    (((*x) >> 12) & 0x0000000f)
        | (((*x) & 0x00000fff) << 4)
        | (((*x) >> 2) & 0x3fff0000)
        | (((*x) & 0x00030000) << 14)
}

#[inline]
pub(crate) fn key_triple_update_0(x: &u32) -> u32 {
    ror(&(*x & 0x33333333), &24) | ror(&(*x & 0xcccccccc), &16)
}

#[inline]
pub(crate) fn key_double_update_1(x: &u32) -> u32 {
    (((x) >> 4) & 0x0f000f00)
        | (((x) & 0x0f000f00) << 4)
        | (((x) >> 6) & 0x00030003)
        | (((x) & 0x003f003f) << 2)
}

#[inline]
pub(crate) fn key_triple_update_1(x: &u32) -> u32 {
    (((x) >> 6) & 0x03000300)
        | (((x) & 0x3f003f00) << 2)
        | (((x) >> 5) & 0x00070007)
        | (((x) & 0x001f001f) << 3)
}

#[inline]
pub(crate) fn key_double_update_2(x: &u32) -> u32 {
    ror(&(*x & 0xaaaaaaaa), &24) | ror(&(*x & 0x55555555), &16)
}

#[inline]
pub(crate) fn key_triple_update_2(x: &u32) -> u32 {
    ror(&(*x & 0x55555555), &24) | ror(&(*x & 0xaaaaaaaa), &20)
}

#[inline]
pub(crate) fn key_double_update_3(x: &u32) -> u32 {
    (((x) >> 2) & 0x03030303)
        | (((x) & 0x03030303) << 2)
        | (((x) >> 1) & 0x70707070)
        | (((x) & 0x10101010) << 3)
}

#[inline]
pub(crate) fn key_triple_update_3(x: &u32) -> u32 {
    (((x) >> 18) & 0x00003030)
        | (((x) & 0x01010101) << 3)
        | (((x) >> 14) & 0x0000c0c0)
        | (((x) & 0x0000e0e0) << 15)
        | (((x) >> 1) & 0x07070707)
        | (((x) & 0x00001010) << 19)
}

#[inline]
pub(crate) fn key_double_update_4(x: &u32) -> u32 {
    (((x) >> 4) & 0x0fff0000)
        | (((x) & 0x000f0000) << 12)
        | (((x) >> 8) & 0x000000ff)
        | (((x) & 0x000000ff) << 8)
}

#[inline]
pub(crate) fn key_triple_update_4(x: &u32) -> u32 {
    (((x) >> 6) & 0x03ff0000)
        | (((x) & 0x003f0000) << 10)
        | (((x) >> 4) & 0x00000fff)
        | (((x) & 0x0000000f) << 12)
}
