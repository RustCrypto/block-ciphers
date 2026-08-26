use crate::primitives::{ror, swapmovesingle, u32big};

fn rearrange_rkey_0(x: &u32) -> u32 {
    let mut tmp = *x;
    swapmovesingle(&mut tmp, 0x00550055, 9);
    swapmovesingle(&mut tmp, 0x000f000f, 12);
    swapmovesingle(&mut tmp, 0x00003333, 18);
    swapmovesingle(&mut tmp, 0x000000ff, 24);
    tmp
}

fn rearrange_rkey_1(x: &u32) -> u32 {
    let mut tmp = *x;
    swapmovesingle(&mut tmp, 0x11111111, 3);
    swapmovesingle(&mut tmp, 0x03030303, 6);
    swapmovesingle(&mut tmp, 0x000f000f, 12);
    swapmovesingle(&mut tmp, 0x000000ff, 24);
    tmp
}

fn rearrange_rkey_2(x: &u32) -> u32 {
    let mut tmp = *x;
    swapmovesingle(&mut tmp, 0x0000aaaa, 15);
    swapmovesingle(&mut tmp, 0x00003333, 18);
    swapmovesingle(&mut tmp, 0x0000f0f0, 12);
    swapmovesingle(&mut tmp, 0x000000ff, 24);
    tmp
}

fn rearrange_rkey_3(x: &u32) -> u32 {
    let mut tmp = *x;
    swapmovesingle(&mut tmp, 0x0a0a0a0a, 3);
    swapmovesingle(&mut tmp, 0x00cc00cc, 6);
    swapmovesingle(&mut tmp, 0x0000f0f0, 12);
    swapmovesingle(&mut tmp, 0x000000ff, 24);
    tmp
}

fn key_update(x: &u32) -> u32 {
    (((*x) >> 12) & 0x0000000f)
        | (((*x) & 0x00000fff) << 4)
        | (((*x) >> 2) & 0x3fff0000)
        | (((*x) & 0x00030000) << 14)
}

fn key_triple_update_0(x: &u32) -> u32 {
    ror(&(*x & 0x33333333), &24) | ror(&(*x & 0xcccccccc), &16)
}

fn key_double_update_1(x: &u32) -> u32 {
    (((x) >> 4) & 0x0f000f00)
        | (((x) & 0x0f000f00) << 4)
        | (((x) >> 6) & 0x00030003)
        | (((x) & 0x003f003f) << 2)
}

fn key_triple_update_1(x: &u32) -> u32 {
    (((x) >> 6) & 0x03000300)
        | (((x) & 0x3f003f00) << 2)
        | (((x) >> 5) & 0x00070007)
        | (((x) & 0x001f001f) << 3)
}

fn key_double_update_2(x: &u32) -> u32 {
    ror(&(*x & 0xaaaaaaaa), &24) | ror(&(*x & 0x55555555), &16)
}

fn key_triple_update_2(x: &u32) -> u32 {
    ror(&(*x & 0x55555555), &24) | ror(&(*x & 0xaaaaaaaa), &20)
}

fn key_double_update_3(x: &u32) -> u32 {
    (((x) >> 2) & 0x03030303)
        | (((x) & 0x03030303) << 2)
        | (((x) >> 1) & 0x70707070)
        | (((x) & 0x10101010) << 3)
}

fn key_triple_update_3(x: &u32) -> u32 {
    (((x) >> 18) & 0x00003030)
        | (((x) & 0x01010101) << 3)
        | (((x) >> 14) & 0x0000c0c0)
        | (((x) & 0x0000e0e0) << 15)
        | (((x) >> 1) & 0x07070707)
        | (((x) & 0x00001010) << 19)
}

fn key_double_update_4(x: &u32) -> u32 {
    (((x) >> 4) & 0x0fff0000)
        | (((x) & 0x000f0000) << 12)
        | (((x) >> 8) & 0x000000ff)
        | (((x) & 0x000000ff) << 8)
}

fn key_triple_update_4(x: &u32) -> u32 {
    (((x) >> 6) & 0x03ff0000)
        | (((x) & 0x003f0000) << 10)
        | (((x) >> 4) & 0x00000fff)
        | (((x) & 0x0000000f) << 12)
}

pub fn precompute_rkeys(key: &[u8; 16]) -> [u32; 80] {
    let mut rkey = [0u32; 80];
    rkey[0] = u32big(&(key[12..16]));
    rkey[1] = u32big(&(key[4..8]));
    rkey[2] = u32big(&(key[8..12]));
    rkey[3] = u32big(&(key[0..4]));

    for i in (0..16).step_by(2) {
        rkey[i + 4] = rkey[i + 1];
        rkey[i + 5] = key_update(&rkey[i]);
    }

    for i in (0..20).step_by(10) {
        rkey[i] = rearrange_rkey_0(&rkey[i]);
        rkey[i + 1] = rearrange_rkey_0(&rkey[i + 1]);
        rkey[i + 2] = rearrange_rkey_1(&rkey[i + 2]);
        rkey[i + 3] = rearrange_rkey_1(&rkey[i + 3]);
        rkey[i + 4] = rearrange_rkey_2(&rkey[i + 4]);
        rkey[i + 5] = rearrange_rkey_2(&rkey[i + 5]);
        rkey[i + 6] = rearrange_rkey_3(&rkey[i + 6]);
        rkey[i + 7] = rearrange_rkey_3(&rkey[i + 7]);
    }

    for i in (20..80).step_by(10) {
        rkey[i] = rkey[i - 19];
        rkey[i + 1] = key_triple_update_0(&rkey[i - 20]);
        rkey[i + 2] = key_double_update_1(&rkey[i - 17]);
        rkey[i + 3] = key_triple_update_1(&rkey[i - 18]);
        rkey[i + 4] = key_double_update_2(&rkey[i - 15]);
        rkey[i + 5] = key_triple_update_2(&rkey[i - 16]);
        rkey[i + 6] = key_double_update_3(&rkey[i - 13]);
        rkey[i + 7] = key_triple_update_3(&rkey[i - 14]);
        rkey[i + 8] = key_double_update_4(&rkey[i - 11]);
        rkey[i + 9] = key_triple_update_4(&rkey[i - 12]);
        swapmovesingle(&mut rkey[i], 0x00003333, 16);
        swapmovesingle(&mut rkey[i], 0x55554444, 1);
        swapmovesingle(&mut rkey[i + 1], 0x55551100, 1);
    }

    rkey
}
