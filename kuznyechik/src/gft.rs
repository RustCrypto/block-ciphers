//! Pre-computed multiplication tables for coefficients of the linear transform

pub(crate) const GFT_16: [u8; 256] = mul_table_gf256(16);
pub(crate) const GFT_32: [u8; 256] = mul_table_gf256(32);
pub(crate) const GFT_133: [u8; 256] = mul_table_gf256(133);
pub(crate) const GFT_148: [u8; 256] = mul_table_gf256(148);
pub(crate) const GFT_192: [u8; 256] = mul_table_gf256(192);
pub(crate) const GFT_194: [u8; 256] = mul_table_gf256(194);
pub(crate) const GFT_251: [u8; 256] = mul_table_gf256(251);

const fn mul_gf256(mut a: u8, mut b: u8) -> u8 {
    let mut c = 0;
    while b != 0 {
        if b & 1 != 0 {
            c ^= a;
        }
        a = (a << 1) ^ if a & 0x80 != 0 { 0xC3 } else { 0x00 };
        b >>= 1;
    }
    c
}

const fn mul_table_gf256(a: u8) -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut i = 0;
    while i < table.len() {
        table[i] = mul_gf256(a, i as u8);
        i += 1;
    }
    table
}
