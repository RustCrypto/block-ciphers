#[inline]
pub(crate) fn u32big(x: &[u8]) -> u32 {
    ((x[0] as u32) << 24) | ((x[1] as u32) << 16) | ((x[2] as u32) << 8) | (x[3] as u32)
}

#[inline]
pub(crate) fn ror(x: &u32, y: &u32) -> u32 {
    ((*x) >> (*y)) | (*x << (32 - (*y)))
}

#[inline]
pub(crate) fn byte_ror_2(x: &u32) -> u32 {
    (((x) >> 2) & 0x3f3f3f3f) | (((x) & 0x03030303) << 6)
}

#[inline]
pub(crate) fn byte_ror_4(x: &u32) -> u32 {
    (((x) >> 4) & 0x0f0f0f0f) | (((x) & 0x0f0f0f0f) << 4)
}

#[inline]
pub(crate) fn byte_ror_6(x: &u32) -> u32 {
    (((x) >> 6) & 0x03030303) | (((x) & 0x3f3f3f3f) << 2)
}

#[inline]
pub(crate) fn half_ror_4(&x: &u32) -> u32 {
    (((x) >> 4) & 0x0fff0fff) | (((x) & 0x000f000f) << 12)
}

#[inline]
pub(crate) fn half_ror_8(x: &u32) -> u32 {
    (((x) >> 8) & 0x00ff00ff) | (((x) & 0x00ff00ff) << 8)
}

#[inline]
pub(crate) fn half_ror_12(&x: &u32) -> u32 {
    (((x) >> 12) & 0x000f000f) | (((x) & 0x0fff0fff) << 4)
}

#[inline]
pub(crate) fn nibble_ror_1(x: &u32) -> u32 {
    (((x) >> 1) & 0x77777777) | (((x) & 0x11111111) << 3)
}

#[inline]
pub(crate) fn nibble_ror_2(x: &u32) -> u32 {
    (((x) >> 2) & 0x33333333) | (((x) & 0x33333333) << 2)
}

#[inline]
pub(crate) fn nibble_ror_3(&x: &u32) -> u32 {
    (((x) >> 3) & 0x11111111) | (((x) & 0x77777777) << 1)
}

#[inline]
pub(crate) fn swapmove(a: &mut u32, b: &mut u32, mask: u32, n: u8) {
    let tmp = (*b ^ (*a >> n)) & mask;
    *b ^= tmp;
    *a ^= tmp << n;
}

#[inline]
pub(crate) fn swapmovesingle(a: &mut u32, mask: u32, n: u8) {
    let tmp = (*a ^ (*a >> n)) & mask;
    *a ^= tmp;
    *a ^= tmp << n;
}

#[inline]
pub(crate) fn sbox(s0: &mut u32, s1: &mut u32, s2: &mut u32, s3: &mut u32) {
    *s1 ^= *s0 & *s2;
    *s0 ^= *s1 & *s3;
    *s2 ^= *s0 | *s1;
    *s3 ^= *s2;
    *s1 ^= *s3;
    *s3 ^= 0xffffffff;
    *s2 ^= *s0 & *s1;
}

#[inline]
pub(crate) fn inv_sbox(s0: &mut u32, s1: &mut u32, s2: &mut u32, s3: &mut u32) {
    *s2 ^= *s3 & *s1;
    *s0 ^= 0xffffffff;
    *s1 ^= *s0;
    *s0 ^= *s2;
    *s2 ^= *s3 | *s1;
    *s3 ^= *s1 & *s0;
    *s1 ^= *s3 & *s2;
}

#[inline]
pub(crate) fn packing(state: &mut [u32], input: &[u8]) {
    let mut s0 = ((input[6] as u32) << 24)
        | ((input[7] as u32) << 16)
        | ((input[14] as u32) << 8)
        | input[15] as u32;
    let mut s1 = ((input[4] as u32) << 24)
        | ((input[5] as u32) << 16)
        | ((input[12] as u32) << 8)
        | input[13] as u32;
    let mut s2 = ((input[2] as u32) << 24)
        | ((input[3] as u32) << 16)
        | ((input[10] as u32) << 8)
        | input[11] as u32;
    let mut s3 = ((input[0] as u32) << 24)
        | ((input[1] as u32) << 16)
        | ((input[8] as u32) << 8)
        | input[9] as u32;
    swapmovesingle(&mut s0, 0x0a0a0a0a, 3);
    swapmovesingle(&mut s0, 0x00cc00cc, 6);
    swapmovesingle(&mut s1, 0x0a0a0a0a, 3);
    swapmovesingle(&mut s1, 0x00cc00cc, 6);
    swapmovesingle(&mut s2, 0x0a0a0a0a, 3);
    swapmovesingle(&mut s2, 0x00cc00cc, 6);
    swapmovesingle(&mut s3, 0x0a0a0a0a, 3);
    swapmovesingle(&mut s3, 0x00cc00cc, 6);
    swapmove(&mut s0, &mut s1, 0x000f000f, 4);
    swapmove(&mut s0, &mut s2, 0x000f000f, 8);
    swapmove(&mut s0, &mut s3, 0x000f000f, 12);
    swapmove(&mut s1, &mut s2, 0x00f000f0, 4);
    swapmove(&mut s1, &mut s3, 0x00f000f0, 8);
    swapmove(&mut s2, &mut s3, 0x0f000f00, 4);
    (state[0], state[1], state[2], state[3]) = (s0, s1, s2, s3);
}

#[inline]
pub(crate) fn unpacking(state: &[u32], output: &mut [u8]) {
    let (mut s0, mut s1, mut s2, mut s3) = (state[0], state[1], state[2], state[3]);

    swapmove(&mut s2, &mut s3, 0x0f000f00, 4);
    swapmove(&mut s1, &mut s3, 0x00f000f0, 8);
    swapmove(&mut s1, &mut s2, 0x00f000f0, 4);
    swapmove(&mut s0, &mut s3, 0x000f000f, 12);
    swapmove(&mut s0, &mut s2, 0x000f000f, 8);
    swapmove(&mut s0, &mut s1, 0x000f000f, 4);
    swapmovesingle(&mut s3, 0x00cc00cc, 6);
    swapmovesingle(&mut s3, 0x0a0a0a0a, 3);
    swapmovesingle(&mut s2, 0x00cc00cc, 6);
    swapmovesingle(&mut s2, 0x0a0a0a0a, 3);
    swapmovesingle(&mut s1, 0x00cc00cc, 6);
    swapmovesingle(&mut s1, 0x0a0a0a0a, 3);
    swapmovesingle(&mut s0, 0x00cc00cc, 6);
    swapmovesingle(&mut s0, 0x0a0a0a0a, 3);
    output[0] = (s3 >> 24) as u8;
    output[1] = ((s3 >> 16) & 0xff) as u8;
    output[2] = (s2 >> 24) as u8;
    output[3] = ((s2 >> 16) & 0xff) as u8;
    output[4] = (s1 >> 24) as u8;
    output[5] = ((s1 >> 16) & 0xff) as u8;
    output[6] = (s0 >> 24) as u8;
    output[7] = ((s0 >> 16) & 0xff) as u8;
    output[8] = ((s3 >> 8) & 0xff) as u8;
    output[9] = (s3 & 0xff) as u8;
    output[10] = ((s2 >> 8) & 0xff) as u8;
    output[11] = (s2 & 0xff) as u8;
    output[12] = ((s1 >> 8) & 0xff) as u8;
    output[13] = (s1 & 0xff) as u8;
    output[14] = ((s0 >> 8) & 0xff) as u8;
    output[15] = (s0 & 0xff) as u8;
}

#[inline]
pub(crate) fn quintuple_round(state: &mut [u32; 4], rkey: &[u32], rconst: &[u32]) {
    let mut s0 = state[0];
    let mut s1 = state[1];
    let mut s2 = state[2];
    let mut s3 = state[3];
    sbox(&mut s0, &mut s1, &mut s2, &mut s3);
    s3 = nibble_ror_1(&s3);
    s1 = nibble_ror_2(&s1);
    s2 = nibble_ror_3(&s2);
    s1 ^= rkey[0];
    s2 ^= rkey[1];
    s0 ^= rconst[0];
    sbox(&mut s3, &mut s1, &mut s2, &mut s0);
    s0 = half_ror_4(&s0);
    s1 = half_ror_8(&s1);
    s2 = half_ror_12(&s2);
    s1 ^= rkey[2];
    s2 ^= rkey[3];
    s3 ^= rconst[1];
    sbox(&mut s0, &mut s1, &mut s2, &mut s3);
    s3 = ror(&s3, &16);
    s2 = ror(&s2, &16);
    swapmovesingle(&mut s1, 0x55555555, 1);
    swapmovesingle(&mut s2, 0x00005555, 1);
    swapmovesingle(&mut s3, 0x55550000, 1);
    s1 ^= rkey[4];
    s2 ^= rkey[5];
    s0 ^= rconst[2];
    sbox(&mut s3, &mut s1, &mut s2, &mut s0);
    s0 = byte_ror_6(&s0);
    s1 = byte_ror_4(&s1);
    s2 = byte_ror_2(&s2);
    s1 ^= rkey[6];
    s2 ^= rkey[7];
    s3 ^= rconst[3];
    sbox(&mut s0, &mut s1, &mut s2, &mut s3);
    s3 = ror(&s3, &24);
    s1 = ror(&s1, &16);
    s2 = ror(&s2, &8);
    s1 ^= rkey[8];
    s2 ^= rkey[9];
    s0 ^= rconst[4];
    core::mem::swap(&mut s0, &mut s3);
    (state[0], state[1], state[2], state[3]) = (s0, s1, s2, s3);
}

#[inline]
pub(crate) fn inv_quintuple_round(state: &mut [u32; 4], rkey: &[u32], rconst: &[u32]) {
    let mut s0 = state[0];
    let mut s1 = state[1];
    let mut s2 = state[2];
    let mut s3 = state[3];
    core::mem::swap(&mut s0, &mut s3);
    s1 ^= rkey[8];
    s2 ^= rkey[9];
    s0 ^= rconst[4];
    s3 = ror(&s3, &8);
    s1 = ror(&s1, &16);
    s2 = ror(&s2, &24);
    inv_sbox(&mut s3, &mut s1, &mut s2, &mut s0);
    s1 ^= rkey[6];
    s2 ^= rkey[7];
    s3 ^= rconst[3];
    s0 = byte_ror_2(&s0);
    s1 = byte_ror_4(&s1);
    s2 = byte_ror_6(&s2);
    inv_sbox(&mut s0, &mut s1, &mut s2, &mut s3);
    s1 ^= rkey[4];
    s2 ^= rkey[5];
    s0 ^= rconst[2];
    swapmovesingle(&mut s3, 0x55550000, 1);
    swapmovesingle(&mut s1, 0x55555555, 1);
    swapmovesingle(&mut s2, 0x00005555, 1);
    s3 = ror(&s3, &16);
    s2 = ror(&s2, &16);
    inv_sbox(&mut s3, &mut s1, &mut s2, &mut s0);
    s1 ^= rkey[2];
    s2 ^= rkey[3];
    s3 ^= rconst[1];
    s0 = half_ror_12(&s0);
    s1 = half_ror_8(&s1);
    s2 = half_ror_4(&s2);
    inv_sbox(&mut s0, &mut s1, &mut s2, &mut s3);
    s1 ^= rkey[0];
    s2 ^= rkey[1];
    s0 ^= rconst[0];
    s3 = nibble_ror_3(&s3);
    s1 = nibble_ror_2(&s1);
    s2 = nibble_ror_1(&s2);
    inv_sbox(&mut s3, &mut s1, &mut s2, &mut s0);
    (state[0], state[1], state[2], state[3]) = (s0, s1, s2, s3);
}
