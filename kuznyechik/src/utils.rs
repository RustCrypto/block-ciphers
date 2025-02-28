use crate::gft::{GFT_16, GFT_32, GFT_133, GFT_148, GFT_192, GFT_194, GFT_251};

#[inline(always)]
const fn get_idx(b: usize, i: usize) -> usize {
    b.wrapping_sub(i) & 0x0F
}

#[inline(always)]
const fn get_m(msg: [u8; 16], b: usize, i: usize) -> usize {
    msg[get_idx(b, i)] as usize
}

pub(crate) const fn l_step(mut msg: [u8; 16], i: usize) -> [u8; 16] {
    let mut x = msg[get_idx(15, i)];
    x ^= GFT_148[get_m(msg, 14, i)];
    x ^= GFT_32[get_m(msg, 13, i)];
    x ^= GFT_133[get_m(msg, 12, i)];
    x ^= GFT_16[get_m(msg, 11, i)];
    x ^= GFT_194[get_m(msg, 10, i)];
    x ^= GFT_192[get_m(msg, 9, i)];
    x ^= msg[get_idx(8, i)];
    x ^= GFT_251[get_m(msg, 7, i)];
    x ^= msg[get_idx(6, i)];
    x ^= GFT_192[get_m(msg, 5, i)];
    x ^= GFT_194[get_m(msg, 4, i)];
    x ^= GFT_16[get_m(msg, 3, i)];
    x ^= GFT_133[get_m(msg, 2, i)];
    x ^= GFT_32[get_m(msg, 1, i)];
    x ^= GFT_148[get_m(msg, 0, i)];
    msg[get_idx(15, i)] = x;
    msg
}

#[repr(align(16))]
#[derive(Clone, Copy)]
pub(crate) struct Align16<T>(pub T);

/// Constants used to generate round keys
pub(crate) static KEYGEN: [Align16<[u8; 16]>; 32] = {
    let mut res = [Align16([0u8; 16]); 32];
    let mut n = 0;
    while n < res.len() {
        let mut block = [0u8; 16];
        block[15] = (n + 1) as u8;

        let mut i = 0;
        while i < 16 {
            block = l_step(block, i);
            i += 1;
        }
        res[n].0 = block;
        n += 1;
    }
    res
};
