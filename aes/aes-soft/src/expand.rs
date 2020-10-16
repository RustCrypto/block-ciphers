#![allow(
    clippy::explicit_counter_loop,
    clippy::needless_range_loop,
    clippy::unreadable_literal
)]

use cipher::generic_array::{ArrayLength, GenericArray};

use crate::bitslice::{bit_slice_4x1_with_u16, un_bit_slice_4x1_with_u16, AesOps};
use crate::consts::RCON;

fn ffmulx(x: u32) -> u32 {
    let m1: u32 = 0x80808080;
    let m2: u32 = 0x7f7f7f7f;
    let m3: u32 = 0x0000001b;
    ((x & m2) << 1) ^ (((x & m1) >> 7) * m3)
}

// ffmulx applied twice
fn ffmulx2(x: u32) -> u32 {
    let m4: u32 = 0xC0C0C0C0;
    let m5: u32 = 0x3f3f3f3f;
    let t0 = (x & m5) << 2;
    let t1 = x & m4;
    let t2 = t1 ^ (t1 >> 1);
    t0 ^ (t2 >> 2) ^ (t2 >> 5)
}

fn inv_mcol(x: u32) -> u32 {
    let t0 = x;
    let t1 = t0 ^ t0.rotate_right(8);
    let t2 = t0 ^ ffmulx(t1);
    let t3 = t1 ^ ffmulx2(t2);
    t2 ^ t3 ^ t3.rotate_right(16)
}

fn sub_word(x: u32) -> u32 {
    let bs = bit_slice_4x1_with_u16(x).sub_bytes();
    un_bit_slice_4x1_with_u16(&bs)
}

// The round keys are created without bit-slicing the key data. The individual implementations bit
// slice the round keys returned from this function. This function, and the few functions above, are
// derived from the BouncyCastle AES implementation.
pub fn expand_key<KeySize: ArrayLength<u8>, Rounds: ArrayLength<[u32; 4]>>(
    key: &GenericArray<u8, KeySize>,
) -> (
    GenericArray<[u32; 4], Rounds>,
    GenericArray<[u32; 4], Rounds>,
) {
    let rounds = Rounds::to_usize();
    let key_len = KeySize::to_usize();
    let key_words = match key_len {
        16 => 4,
        24 => 6,
        32 => 8,
        _ => panic!("Invalid AES key size."),
    };
    let mut ek = GenericArray::<[u32; 4], Rounds>::default();

    // The key is copied directly into the first few round keys
    let mut j = 0;
    for i in 0..key_len / 4 {
        ek[j / 4][j % 4] = u32::from(key[4 * i])
            | (u32::from(key[4 * i + 1]) << 8)
            | (u32::from(key[4 * i + 2]) << 16)
            | (u32::from(key[4 * i + 3]) << 24);
        j += 1;
    }

    // Calculate the rest of the round keys
    for i in key_words..rounds * 4 {
        let mut tmp = ek[(i - 1) / 4][(i - 1) % 4];
        if (i % key_words) == 0 {
            tmp = sub_word(tmp.rotate_right(8)) ^ RCON[(i / key_words) - 1];
        } else if (key_words == 8) && ((i % key_words) == 4) {
            // This is only necessary for AES-256 keys
            tmp = sub_word(tmp);
        }
        ek[i / 4][i % 4] = ek[(i - key_words) / 4][(i - key_words) % 4] ^ tmp;
    }

    // Decryption round keys require extra processing
    let mut dk = GenericArray::<[u32; 4], Rounds>::default();
    dk[0] = ek[0];
    for j in 1..rounds - 1 {
        for i in 0..4 {
            dk[j][i] = inv_mcol(ek[j][i]);
        }
    }
    dk[rounds - 1] = ek[rounds - 1];

    (ek, dk)
}
