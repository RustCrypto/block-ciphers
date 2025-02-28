use crate::{
    consts,
    gft::{GFT_16, GFT_32, GFT_133, GFT_148, GFT_192, GFT_194, GFT_251},
    utils::Align16,
};

pub(crate) type Table = Align16<[u8; 16 * 4096]>;
pub(crate) static ENC_TABLE: Table = Align16(fused_enc_table());
pub(crate) static DEC_TABLE: Table = Align16(fused_dec_table());

const fn fused_enc_table() -> [u8; 16 * 4096] {
    let mut table = [0u8; 16 * 4096];

    let mut i = 0;
    let mut pos = 0;
    while i < 16 {
        let mut j = 0;
        while j < 256 {
            table[pos + i] = consts::P[j];

            let mut n = 0;
            while n < 16 {
                let mut x = table[pos + 15];
                x ^= GFT_148[table[pos + 14] as usize];
                x ^= GFT_32[table[pos + 13] as usize];
                x ^= GFT_133[table[pos + 12] as usize];
                x ^= GFT_16[table[pos + 11] as usize];
                x ^= GFT_194[table[pos + 10] as usize];
                x ^= GFT_192[table[pos + 9] as usize];
                x ^= table[pos + 8];
                x ^= GFT_251[table[pos + 7] as usize];
                x ^= table[pos + 6];
                x ^= GFT_192[table[pos + 5] as usize];
                x ^= GFT_194[table[pos + 4] as usize];
                x ^= GFT_16[table[pos + 3] as usize];
                x ^= GFT_133[table[pos + 2] as usize];
                x ^= GFT_32[table[pos + 1] as usize];
                x ^= GFT_148[table[pos] as usize];

                // Strictly speaking, we don't need to move these bytes around because
                // we do 16 iterations. See the `l_step` function for the reference.
                // Unfortunately, we can not use the `l_step` function directly because
                // of const eval limitations.
                let mut k = 15;
                while k > 0 {
                    k -= 1;
                    table[pos + k + 1] = table[pos + k];
                }
                table[pos] = x;

                n += 1;
            }

            j += 1;
            pos += 16;
        }
        i += 1;
    }

    table
}

const fn fused_dec_table() -> [u8; 16 * 4096] {
    let mut table = [0u8; 16 * 4096];

    let mut i = 0;
    let mut pos = 0;
    while i < 16 {
        let mut j = 0;
        while j < 256 {
            table[pos + i] = consts::P_INV[j];

            let mut n = 0;
            while n < 16 {
                let mut x = table[pos];
                x ^= GFT_148[table[pos + 1] as usize];
                x ^= GFT_32[table[pos + 2] as usize];
                x ^= GFT_133[table[pos + 3] as usize];
                x ^= GFT_16[table[pos + 4] as usize];
                x ^= GFT_194[table[pos + 5] as usize];
                x ^= GFT_192[table[pos + 6] as usize];
                x ^= table[pos + 7];
                x ^= GFT_251[table[pos + 8] as usize];
                x ^= table[pos + 9];
                x ^= GFT_192[table[pos + 10] as usize];
                x ^= GFT_194[table[pos + 11] as usize];
                x ^= GFT_16[table[pos + 12] as usize];
                x ^= GFT_133[table[pos + 13] as usize];
                x ^= GFT_32[table[pos + 14] as usize];
                x ^= GFT_148[table[pos + 15] as usize];

                // See comment in the `fused_enc_table` function.
                let mut k = 0;
                while k < 15 {
                    table[pos + k] = table[pos + k + 1];
                    k += 1;
                }
                table[pos + 15] = x;

                n += 1;
            }

            j += 1;
            pos += 16;
        }
        i += 1;
    }
    table
}
