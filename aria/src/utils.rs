use crate::consts::{DIFFUSE_CONSTS, SB1, SB2, SB3, SB4};

#[inline(always)]
fn diffuse(x: [u8; 16]) -> u128 {
    DIFFUSE_CONSTS
        .iter()
        .zip(x)
        .map(|(a, b)| a * b as u128)
        .fold(0, |a, v| a ^ v)
}

#[inline(always)]
pub(crate) fn a(x128: u128) -> u128 {
    diffuse(x128.to_be_bytes())
}

pub(crate) fn sl2(x128: u128) -> u128 {
    let x = x128.to_be_bytes();
    let y = [
        SB3[x[0] as usize],
        SB4[x[1] as usize],
        SB1[x[2] as usize],
        SB2[x[3] as usize],
        SB3[x[4] as usize],
        SB4[x[5] as usize],
        SB1[x[6] as usize],
        SB2[x[7] as usize],
        SB3[x[8] as usize],
        SB4[x[9] as usize],
        SB1[x[10] as usize],
        SB2[x[11] as usize],
        SB3[x[12] as usize],
        SB4[x[13] as usize],
        SB1[x[14] as usize],
        SB2[x[15] as usize],
    ];
    u128::from_be_bytes(y)
}

pub(crate) fn fo(x128: u128) -> u128 {
    let x = x128.to_be_bytes();
    diffuse([
        SB1[x[0] as usize],
        SB2[x[1] as usize],
        SB3[x[2] as usize],
        SB4[x[3] as usize],
        SB1[x[4] as usize],
        SB2[x[5] as usize],
        SB3[x[6] as usize],
        SB4[x[7] as usize],
        SB1[x[8] as usize],
        SB2[x[9] as usize],
        SB3[x[10] as usize],
        SB4[x[11] as usize],
        SB1[x[12] as usize],
        SB2[x[13] as usize],
        SB3[x[14] as usize],
        SB4[x[15] as usize],
    ])
}

pub(crate) fn fe(x128: u128) -> u128 {
    let x = x128.to_be_bytes();
    diffuse([
        SB3[x[0] as usize],
        SB4[x[1] as usize],
        SB1[x[2] as usize],
        SB2[x[3] as usize],
        SB3[x[4] as usize],
        SB4[x[5] as usize],
        SB1[x[6] as usize],
        SB2[x[7] as usize],
        SB3[x[8] as usize],
        SB4[x[9] as usize],
        SB1[x[10] as usize],
        SB2[x[11] as usize],
        SB3[x[12] as usize],
        SB4[x[13] as usize],
        SB1[x[14] as usize],
        SB2[x[15] as usize],
    ])
}
