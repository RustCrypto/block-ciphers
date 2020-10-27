//! Fixsliced implementations of AES-128, AES-192 and AES-256 (encryption-only)
//! adapted from the C implementation.
//!
//! All implementations are fully bitsliced and do not rely on any
//! Look-Up Table (LUT).
//!
//! See the paper at <https://eprint.iacr.org/2020/1123.pdf> for more details.
//!
//! # Author (original C code)
//!
//! Alexandre Adomnicai, Nanyang Technological University, Singapore
//! <alexandre.adomnicai@ntu.edu.sg>
//!
//! Originally licensed MIT. Relicensed as Apache 2.0+MIT with permission.

use crate::Block;
use byteorder::{ByteOrder, LE};
use cipher::{
    consts::{U16, U24, U32},
    generic_array::GenericArray,
};

/// AES-128 round keys
pub(crate) type FixsliceKeys128 = [u32; 88];

/// AES-192 round keys
pub(crate) type FixsliceKeys192 = [u32; 104];

/// AES-256 round keys
pub(crate) type FixsliceKeys256 = [u32; 120];

/// 256-bit internal state
type State = [u32; 8];

/// Fully bitsliced AES-128 key schedule to match the fully-fixsliced representation.
pub(crate) fn aes128_key_schedule(key: &GenericArray<u8, U16>) -> FixsliceKeys128 {
    // TODO(tarcieri): use `::default()` after MSRV 1.47+
    let mut rkeys = [0u32; 88];

    // Pack the keys into the bitsliced state
    packing(&mut rkeys[..8], key, key);

    memshift32(&mut rkeys, 0);
    sbox(&mut rkeys[8..16]);
    rcon_bit(&mut rkeys[8..16], 0);
    xor_columns(&mut rkeys, 8, 8, ror_distance(1, 3));

    memshift32(&mut rkeys, 8);
    sbox(&mut rkeys[16..24]);
    rcon_bit(&mut rkeys[16..24], 1);
    xor_columns(&mut rkeys, 16, 8, ror_distance(1, 3));
    inv_shiftrows_1(&mut rkeys[8..16]); // to match fixslicing

    memshift32(&mut rkeys, 16);
    sbox(&mut rkeys[24..32]);
    rcon_bit(&mut rkeys[24..32], 2);
    xor_columns(&mut rkeys, 24, 8, ror_distance(1, 3));
    inv_shiftrows_2(&mut rkeys[16..24]); // to match fixslicing

    memshift32(&mut rkeys, 24);
    sbox(&mut rkeys[32..40]);
    rcon_bit(&mut rkeys[32..40], 3);
    xor_columns(&mut rkeys, 32, 8, ror_distance(1, 3));
    inv_shiftrows_3(&mut rkeys[24..32]); // to match fixslicing

    memshift32(&mut rkeys, 32);
    sbox(&mut rkeys[40..48]);
    rcon_bit(&mut rkeys[40..48], 4);
    xor_columns(&mut rkeys, 40, 8, ror_distance(1, 3));

    memshift32(&mut rkeys, 40);
    sbox(&mut rkeys[48..56]);
    rcon_bit(&mut rkeys[48..56], 5);
    xor_columns(&mut rkeys, 48, 8, ror_distance(1, 3));
    inv_shiftrows_1(&mut rkeys[40..48]); // to match fixslicing

    memshift32(&mut rkeys, 48);
    sbox(&mut rkeys[56..64]);
    rcon_bit(&mut rkeys[56..64], 6);
    xor_columns(&mut rkeys, 56, 8, ror_distance(1, 3));
    inv_shiftrows_2(&mut rkeys[48..56]); // to match fixslicing

    memshift32(&mut rkeys, 56);
    sbox(&mut rkeys[64..72]);
    rcon_bit(&mut rkeys[64..72], 7);
    xor_columns(&mut rkeys, 64, 8, ror_distance(1, 3));
    inv_shiftrows_3(&mut rkeys[56..64]); // to match fixslicing

    memshift32(&mut rkeys, 64);
    sbox(&mut rkeys[72..80]);
    rcon_bit(&mut rkeys[72..80], 0);
    rcon_bit(&mut rkeys[72..80], 1);
    rcon_bit(&mut rkeys[72..80], 3);
    rcon_bit(&mut rkeys[72..80], 4);
    xor_columns(&mut rkeys, 72, 8, ror_distance(1, 3));

    memshift32(&mut rkeys, 72);
    sbox(&mut rkeys[80..]);
    rcon_bit(&mut rkeys[80..], 1);
    rcon_bit(&mut rkeys[80..], 2);
    rcon_bit(&mut rkeys[80..], 4);
    rcon_bit(&mut rkeys[80..], 5);
    xor_columns(&mut rkeys, 80, 8, ror_distance(1, 3));
    inv_shiftrows_1(&mut rkeys[72..80]);

    // Bitwise NOT to speed up SBox calculations
    for i in 1..11 {
        sbox_nots(&mut rkeys[(i * 8)..(i * 8 + 8)]);
    }

    rkeys
}

/// Fully bitsliced AES-192 key schedule to match the fully-fixsliced representation.
pub(crate) fn aes192_key_schedule(key: &GenericArray<u8, U24>) -> FixsliceKeys192 {
    // TODO(tarcieri): use `::default()` after MSRV 1.47+
    let mut rkeys = [0u32; 104];
    let mut tmp = [0u32; 8];

    // Pack the keys into the bitsliced state
    packing(&mut rkeys[..8], &key[..16], &key[..16]);
    packing(&mut tmp, &key[8..], &key[8..]);

    let mut rcon = 0;
    let mut rk_off = 8;

    loop {
        for i in 0..8 {
            rkeys[rk_off + i] =
                (0x0f0f0f0f & (tmp[i] >> 4)) | (0xf0f0f0f0 & (rkeys[(rk_off - 8) + i] << 4));
        }

        sbox(&mut tmp);
        sbox_nots(&mut tmp);
        rcon_bit(&mut tmp, rcon);
        rcon += 1;

        for i in 0..8 {
            let mut ti = rkeys[rk_off + i];
            ti ^= 0x30303030 & ror(tmp[i], ror_distance(1, 1));
            ti ^= 0xc0c0c0c0 & (ti << 2);
            tmp[i] = ti;
        }
        rkeys[rk_off..(rk_off + 8)].copy_from_slice(&tmp);
        rk_off += 8;

        for i in 0..8 {
            let ui = tmp[i];
            let mut ti = (0x0f0f0f0f & (rkeys[(rk_off - 16) + i] >> 4)) | (0xf0f0f0f0 & (ui << 4));
            ti ^= 0x03030303 & (ui >> 6);
            ti ^= 0x0c0c0c0c & (ti << 2);
            ti ^= 0x30303030 & (ti << 2);
            ti ^= 0xc0c0c0c0 & (ti << 2);
            tmp[i] = ti;
        }
        rkeys[rk_off..(rk_off + 8)].copy_from_slice(&tmp);
        rk_off += 8;

        sbox(&mut tmp);
        sbox_nots(&mut tmp);
        rcon_bit(&mut tmp, rcon);
        rcon += 1;

        for i in 0..8 {
            let mut ti = (0x0f0f0f0f & (rkeys[(rk_off - 16) + i] >> 4))
                | (0xf0f0f0f0 & (rkeys[(rk_off - 8) + i] << 4));
            ti ^= 0x03030303 & ror(tmp[i], ror_distance(1, 3));
            ti ^= 0x0c0c0c0c & (ti << 2);
            ti ^= 0x30303030 & (ti << 2);
            ti ^= 0xc0c0c0c0 & (ti << 2);
            rkeys[rk_off + i] = ti;
        }
        rk_off += 8;

        if rcon >= 8 {
            break;
        }

        for i in 0..8 {
            let ui = rkeys[(rk_off - 8) + i];
            let mut ti = rkeys[(rk_off - 16) + i];
            ti ^= 0x30303030 & (ui >> 2);
            ti ^= 0xc0c0c0c0 & (ti << 2);
            tmp[i] = ti;
        }
    }

    // to match fixslicing
    for i in (0..96).step_by(32) {
        inv_shiftrows_1(&mut rkeys[(i + 8)..(i + 16)]);
        inv_shiftrows_2(&mut rkeys[(i + 16)..(i + 24)]);
        inv_shiftrows_3(&mut rkeys[(i + 24)..(i + 32)]);
    }

    // Bitwise NOT to speed up SBox calculations
    for i in 1..13 {
        sbox_nots(&mut rkeys[(i * 8)..(i * 8 + 8)]);
    }

    rkeys
}

/// Fully bitsliced AES-256 key schedule to match the fully-fixsliced representation.
pub(crate) fn aes256_key_schedule(key: &GenericArray<u8, U32>) -> FixsliceKeys256 {
    // TODO(tarcieri): use `::default()` after MSRV 1.47+
    let mut rkeys = [0u32; 120];

    // Pack the keys into the bitsliced state
    packing(&mut rkeys[..8], &key[..16], &key[..16]);
    packing(&mut rkeys[8..16], &key[16..], &key[16..]);

    memshift32(&mut rkeys, 8);
    sbox(&mut rkeys[16..24]);
    rcon_bit(&mut rkeys[16..24], 0);
    xor_columns(&mut rkeys, 16, 16, ror_distance(1, 3));

    memshift32(&mut rkeys, 16);
    sbox(&mut rkeys[24..32]);
    xor_columns(&mut rkeys, 24, 16, ror_distance(0, 3));
    inv_shiftrows_1(&mut rkeys[8..16]); // to match fixslicing

    memshift32(&mut rkeys, 24);
    sbox(&mut rkeys[32..40]);
    rcon_bit(&mut rkeys[32..40], 1);
    xor_columns(&mut rkeys, 32, 16, ror_distance(1, 3));
    inv_shiftrows_2(&mut rkeys[16..24]); // to match fixslicing

    memshift32(&mut rkeys, 32);
    sbox(&mut rkeys[40..48]);
    xor_columns(&mut rkeys, 40, 16, ror_distance(0, 3));
    inv_shiftrows_3(&mut rkeys[24..32]); // to match fixslicing

    memshift32(&mut rkeys, 40);
    sbox(&mut rkeys[48..56]);
    rcon_bit(&mut rkeys[48..56], 2);
    xor_columns(&mut rkeys, 48, 16, ror_distance(1, 3));

    memshift32(&mut rkeys, 48);
    sbox(&mut rkeys[56..64]);
    xor_columns(&mut rkeys, 56, 16, ror_distance(0, 3));
    inv_shiftrows_1(&mut rkeys[40..48]); // to match fixslicing

    memshift32(&mut rkeys, 56);
    sbox(&mut rkeys[64..72]);
    rcon_bit(&mut rkeys[64..72], 3);
    xor_columns(&mut rkeys, 64, 16, ror_distance(1, 3));
    inv_shiftrows_2(&mut rkeys[48..56]); // to match fixslicing

    memshift32(&mut rkeys, 64);
    sbox(&mut rkeys[72..80]);
    xor_columns(&mut rkeys, 72, 16, ror_distance(0, 3));
    inv_shiftrows_3(&mut rkeys[56..64]); // to match fixslicing

    memshift32(&mut rkeys, 72);
    sbox(&mut rkeys[80..88]);
    rcon_bit(&mut rkeys[80..88], 4);
    xor_columns(&mut rkeys, 80, 16, ror_distance(1, 3));

    memshift32(&mut rkeys, 80);
    sbox(&mut rkeys[88..96]);
    xor_columns(&mut rkeys, 88, 16, ror_distance(0, 3));
    inv_shiftrows_1(&mut rkeys[72..80]); // to match fixslicing

    memshift32(&mut rkeys, 88);
    sbox(&mut rkeys[96..104]);
    rcon_bit(&mut rkeys[96..104], 5);
    xor_columns(&mut rkeys, 96, 16, ror_distance(1, 3));
    inv_shiftrows_2(&mut rkeys[80..88]); // to match fixslicing

    memshift32(&mut rkeys, 96);
    sbox(&mut rkeys[104..112]);
    xor_columns(&mut rkeys, 104, 16, ror_distance(0, 3));
    inv_shiftrows_3(&mut rkeys[88..96]); // to match fixslicing

    memshift32(&mut rkeys, 104);
    sbox(&mut rkeys[112..]);
    rcon_bit(&mut rkeys[112..], 6);
    xor_columns(&mut rkeys, 112, 16, ror_distance(1, 3));

    inv_shiftrows_1(&mut rkeys[104..112]); // to match fixslicing

    // Bitwise NOT to speed up SBox calculations
    for i in 1..15 {
        sbox_nots(&mut rkeys[(i * 8)..(i * 8 + 8)]);
    }

    rkeys
}

/// Fully-fixsliced AES-128 encryption (the ShiftRows is completely omitted).
///
/// Encrypts two blocks in-place and in parallel.
pub(crate) fn aes128_encrypt(rkeys: &FixsliceKeys128, blocks: &mut [Block]) {
    debug_assert_eq!(blocks.len(), 2);
    let mut state = State::default();

    // packs into bitsliced representation
    packing(&mut state, &blocks[0], &blocks[1]);
    ark(&mut state, &rkeys[..8]);

    // 1st round
    sbox(&mut state);
    mixcolumns_0(&mut state);
    ark(&mut state, &rkeys[8..16]);

    // 2nd round
    sbox(&mut state);
    mixcolumns_1(&mut state);
    ark(&mut state, &rkeys[16..24]);

    // 3rd round
    sbox(&mut state);
    mixcolumns_2(&mut state);
    ark(&mut state, &rkeys[24..32]);

    // 4th round
    sbox(&mut state);
    mixcolumns_3(&mut state);
    ark(&mut state, &rkeys[32..40]);

    // 5th round
    sbox(&mut state);
    mixcolumns_0(&mut state);
    ark(&mut state, &rkeys[40..48]);

    // 6th round
    sbox(&mut state);
    mixcolumns_1(&mut state);
    ark(&mut state, &rkeys[48..56]);

    // 7th round
    sbox(&mut state);
    mixcolumns_2(&mut state);
    ark(&mut state, &rkeys[56..64]);

    // 8th round
    sbox(&mut state);
    mixcolumns_3(&mut state);
    ark(&mut state, &rkeys[64..72]);

    // 9th round
    sbox(&mut state);
    mixcolumns_0(&mut state);
    ark(&mut state, &rkeys[72..80]);

    // 10th round
    sbox(&mut state);
    double_shiftrows(&mut state); // resynchronization
    ark(&mut state, &rkeys[80..]);

    // Unpack state into output
    unpacking(&mut state, blocks);
}

/// Fully-fixsliced AES-192 encryption (the ShiftRows is completely omitted).
///
/// Encrypts two blocks in-place and in parallel.
pub(crate) fn aes192_encrypt(rkeys: &FixsliceKeys192, blocks: &mut [Block]) {
    debug_assert_eq!(blocks.len(), 2);
    let mut state = State::default();

    // Pack into bitsliced representation
    packing(&mut state, &blocks[0], &blocks[1]);

    // Loop over quadruple rounds
    for i in (0..64).step_by(32) {
        ark(&mut state, &rkeys[i..(i + 8)]);
        sbox(&mut state);
        mixcolumns_0(&mut state);

        ark(&mut state, &rkeys[(i + 8)..(i + 16)]);
        sbox(&mut state);
        mixcolumns_1(&mut state);

        ark(&mut state, &rkeys[(i + 16)..(i + 24)]);
        sbox(&mut state);
        mixcolumns_2(&mut state);

        ark(&mut state, &rkeys[(i + 24)..(i + 32)]);
        sbox(&mut state);
        mixcolumns_3(&mut state);
    }

    ark(&mut state, &rkeys[64..72]);
    sbox(&mut state);
    mixcolumns_0(&mut state);

    ark(&mut state, &rkeys[72..80]);
    sbox(&mut state);
    mixcolumns_1(&mut state);

    ark(&mut state, &rkeys[80..88]);
    sbox(&mut state);
    mixcolumns_2(&mut state);

    ark(&mut state, &rkeys[88..96]);
    sbox(&mut state);
    // No resynchronization needed
    ark(&mut state, &rkeys[96..104]);

    // Unpack state into output
    unpacking(&mut state, blocks);
}

/// Fully-fixsliced AES-256 encryption (the ShiftRows is completely omitted).
///
/// Encrypts two blocks in-place and in parallel.
pub(crate) fn aes256_encrypt(rkeys: &FixsliceKeys256, blocks: &mut [Block]) {
    debug_assert_eq!(blocks.len(), 2);
    let mut state = State::default();

    // Pack into bitsliced representation
    packing(&mut state, &blocks[0], &blocks[1]);

    // Loop over quadruple rounds
    for i in (0..96).step_by(32) {
        ark(&mut state, &rkeys[i..(i + 8)]);
        sbox(&mut state);
        mixcolumns_0(&mut state);

        ark(&mut state, &rkeys[(i + 8)..(i + 16)]);
        sbox(&mut state);
        mixcolumns_1(&mut state);

        ark(&mut state, &rkeys[(i + 16)..(i + 24)]);
        sbox(&mut state);
        mixcolumns_2(&mut state);

        ark(&mut state, &rkeys[(i + 24)..(i + 32)]);
        sbox(&mut state);
        mixcolumns_3(&mut state);
    }

    ark(&mut state, &rkeys[96..104]);
    sbox(&mut state);
    mixcolumns_0(&mut state);

    ark(&mut state, &rkeys[104..112]);
    sbox(&mut state);
    double_shiftrows(&mut state); // resynchronization
    ark(&mut state, &rkeys[112..]);

    // Unpack state into output
    unpacking(&mut state, blocks);
}

/// Bitsliced implementation of the AES Sbox based on Boyar, Peralta and Calik.
///
/// See: <http://www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt>
///
/// Note that the 4 bitwise NOT (^= 0xffffffff) are moved to the key schedule.
/// They are deliberately retained below (commented out) for illustrative purposes.
fn sbox(state: &mut [u32]) {
    debug_assert_eq!(state.len(), 8);

    let mut t0 = state[4] ^ state[2];
    let mut t1 = state[7] ^ state[1];
    let mut t2 = t1 ^ t0;
    let mut t3 = state[3] ^ t2;
    let mut t4 = t3 ^ state[2];
    let mut t5 = t2 & t4;
    let mut t6 = t4 ^ state[0];
    let mut t7 = t3 ^ state[6];
    let t8 = state[7] ^ state[4];
    let t9 = t7 ^ t8;
    let mut t10 = t8 & t9;
    let mut t11 = state[0] ^ t9;
    let mut t12 = state[7] ^ state[2];
    let mut t13 = state[6] ^ state[5];
    let mut t14 = t4 ^ t13;
    let mut t15 = t14 ^ t9;
    let mut t16 = t0 & t15;
    let mut t17 = t16 ^ t10;
    state[6] = t14 ^ t12;
    state[5] = t12 & t14;
    state[5] ^= t10;
    state[3] = t13 ^ t9;
    state[2] = t1 ^ state[3];
    t3 = t1 & state[3];
    t10 = state[7] ^ state[3];
    t13 ^= state[0];
    state[4] ^= t13;
    t16 = state[4] & state[0];
    t16 ^= t5;
    t16 ^= state[5];
    state[6] ^= t16;
    state[7] ^= t13;
    t16 = state[7] & t11;
    t16 ^= t3;
    state[5] ^= t16;
    state[5] ^= t10;
    state[1] ^= t13;
    t10 = state[1] & t13;
    t3 ^= t10;
    t3 ^= t17;
    state[2] ^= t3;
    t3 = state[1] ^ t12;
    t10 = t3 & t6;
    t5 ^= t10;
    t5 ^= t7;
    t5 ^= t17;
    t7 = t5 & state[2];
    t10 = state[5] ^ t7;
    t7 ^= state[6];
    t5 ^= state[6];
    t16 = t5 & t10;
    state[6] ^= t16;
    t17 = state[6] & state[7];
    t11 &= state[6];
    t16 = state[2] ^ state[5];
    t7 &= t16;
    t7 ^= state[5];
    t16 = t10 ^ t7;
    state[5] &= t16;
    t10 ^= state[5];
    t10 &= state[6];
    t5 ^= t10;
    t10 = state[6] ^ t5;
    state[3] &= t10;
    t11 ^= state[3];
    t1 &= t10;
    state[1] &= t5;
    t10 = t5 & t13;
    state[3] ^= t10;
    state[2] ^= t7;
    state[5] ^= state[2];
    state[2] = t5 ^ state[5];
    t5 = state[2] & t14;
    t10 = state[2] & t12;
    t12 = t7 ^ state[5];
    t4 &= t12;
    t2 &= t12;
    t3 &= state[5];
    state[5] &= t6;
    state[5] ^= t4;
    t13 = state[3] ^ state[5];
    state[4] &= t7;
    state[6] ^= t7;
    state[2] ^= state[6];
    t6 = state[2] & t15;
    state[3] ^= t6;
    t0 &= state[2];
    state[2] = state[6] & t9;
    state[2] ^= state[3];
    state[6] &= t8;
    t6 = state[6] ^ state[2];
    t0 ^= state[6];
    state[6] = t3 ^ t0;
    t15 = state[6] ^ state[4];
    t2 ^= state[6];
    state[7] = t2 ^ state[2];
    state[4] = t2 ^ t13;
    state[6] = state[4] ^ state[2];
    //state[6] ^= 0xffffffff;
    t0 ^= state[1];
    state[2] = t7 & state[0];
    t14 = t4 ^ state[2];
    state[1] = t1 ^ t14;
    state[1] ^= t5;
    state[1] ^= state[3];
    state[5] = t17 ^ state[1];
    state[2] = t15 ^ state[5];
    state[5] ^= t6;
    state[5] ^= t10;
    //state[5] ^= 0xffffffff;
    t14 ^= t11;
    t0 ^= t14;
    state[1] ^= t0;
    //state[1] ^= 0xffffffff;
    state[0] = t1 ^ t0;
    //state[0] ^= 0xffffffff;
    state[3] = t14 ^ state[4];
}

/// NOT operations that are omitted in S-box
#[inline]
fn sbox_nots(state: &mut [u32]) {
    debug_assert_eq!(state.len(), 8);
    state[0] ^= 0xffffffff;
    state[1] ^= 0xffffffff;
    state[5] ^= 0xffffffff;
    state[6] ^= 0xffffffff;
}

/// Computation of the MixColumns transformation in the fixsliced representation
/// used for rounds i s.t. (i%4) == 0.
fn mixcolumns_0(state: &mut State) {
    let mut tmp3 = rotate_rows_1(rotate_columns_3(state[7]));
    let tmp0 = state[7] ^ tmp3;
    let mut tmp2 = state[1];
    state[1] = state[0] ^ tmp0;
    let mut tmp1 = rotate_rows_1(rotate_columns_3(state[0]));
    state[1] ^= tmp1;
    state[0] ^= state[1];
    tmp1 = rotate_rows_1(rotate_columns_3(tmp1));
    tmp1 ^= rotate_rows_1(rotate_columns_3(tmp1));
    state[0] ^= tmp1;
    tmp1 = rotate_rows_1(rotate_columns_3(tmp2));
    state[1] ^= tmp1;
    tmp2 ^= tmp1;
    tmp1 = rotate_rows_1(rotate_columns_3(tmp1));
    tmp1 ^= rotate_rows_1(rotate_columns_3(tmp1));
    state[1] ^= tmp1;
    tmp1 = state[2];
    state[2] = tmp2;
    tmp2 = rotate_rows_1(rotate_columns_3(tmp1));
    tmp1 ^= tmp2;
    state[2] ^= tmp2;
    tmp2 = rotate_rows_1(rotate_columns_3(tmp2));
    tmp2 ^= rotate_rows_1(rotate_columns_3(tmp2));
    state[2] ^= tmp2;
    tmp2 = state[3];
    state[3] = tmp1;
    tmp1 = rotate_rows_1(rotate_columns_3(tmp2));
    tmp2 ^= tmp1;
    state[3] ^= tmp0 ^ tmp1;
    tmp1 = rotate_rows_1(rotate_columns_3(tmp1));
    tmp1 ^= rotate_rows_1(rotate_columns_3(tmp1));
    state[3] ^= tmp1;
    tmp1 = state[4];
    state[4] = tmp0 ^ tmp2;
    tmp2 = rotate_rows_1(rotate_columns_3(tmp1));
    tmp1 ^= tmp2;
    state[4] ^= tmp2;
    tmp2 = rotate_rows_1(rotate_columns_3(tmp2));
    tmp2 ^= rotate_rows_1(rotate_columns_3(tmp2));
    state[4] ^= tmp2;
    tmp2 = state[5];
    state[5] = tmp1;
    tmp1 = rotate_rows_1(rotate_columns_3(tmp2));
    tmp2 ^= tmp1;
    state[5] ^= tmp1;
    tmp1 = rotate_rows_1(rotate_columns_3(tmp1));
    tmp1 ^= rotate_rows_1(rotate_columns_3(tmp1));
    state[5] ^= tmp1;
    tmp1 = state[6];
    state[6] = tmp2;
    tmp2 = rotate_rows_1(rotate_columns_3(tmp1));
    tmp1 ^= tmp2;
    state[6] ^= tmp2;
    tmp2 = rotate_rows_1(rotate_columns_3(tmp2));
    tmp2 ^= rotate_rows_1(rotate_columns_3(tmp2));
    state[6] ^= tmp2;
    state[7] = tmp1;
    state[7] ^= tmp3;
    tmp3 = rotate_rows_1(rotate_columns_3(tmp3));
    tmp3 ^= rotate_rows_1(rotate_columns_3(tmp3));
    state[7] ^= tmp3;
}

/// Computation of the MixColumns transformation in the fixsliced representation
/// used for round i s.t. (i%4) == 1.
fn mixcolumns_1(state: &mut State) {
    let tmp0 = state[7] ^ rotate_rows_1(rotate_columns_2(state[7]));
    let mut tmp1 = state[0] ^ rotate_rows_1(rotate_columns_2(state[0]));
    let mut tmp2 = state[1];
    state[1] = tmp1 ^ tmp0;
    state[0] ^= state[1] ^ rotate_rows_2(tmp1);
    tmp1 = rotate_rows_1(rotate_columns_2(tmp2));
    state[1] ^= tmp1;
    tmp1 ^= tmp2;
    state[1] ^= rotate_rows_2(tmp1);
    tmp2 = state[2];
    state[2] = tmp1;
    tmp1 = rotate_rows_1(rotate_columns_2(tmp2));
    state[2] ^= tmp1;
    tmp1 ^= tmp2;
    state[2] ^= rotate_rows_2(tmp1);
    tmp2 = state[3];
    state[3] = tmp1 ^ tmp0;
    tmp1 = rotate_rows_1(rotate_columns_2(tmp2));
    state[3] ^= tmp1;
    tmp1 ^= tmp2;
    state[3] ^= rotate_rows_2(tmp1);
    tmp2 = state[4];
    state[4] = tmp1 ^ tmp0;
    tmp1 = rotate_rows_1(rotate_columns_2(tmp2));
    state[4] ^= tmp1;
    tmp1 ^= tmp2;
    state[4] ^= rotate_rows_2(tmp1);
    tmp2 = state[5];
    state[5] = tmp1;
    tmp1 = rotate_rows_1(rotate_columns_2(tmp2));
    state[5] ^= tmp1;
    tmp1 ^= tmp2;
    state[5] ^= rotate_rows_2(tmp1);
    tmp2 = state[6];
    state[6] = tmp1;
    tmp1 = rotate_rows_1(rotate_columns_2(tmp2));
    state[6] ^= tmp1;
    tmp1 ^= tmp2;
    state[6] ^= rotate_rows_2(tmp1);
    tmp2 = state[7];
    state[7] = tmp1;
    tmp1 = rotate_rows_1(rotate_columns_2(tmp2));
    state[7] ^= tmp1;
    tmp1 ^= tmp2;
    state[7] ^= rotate_rows_2(tmp1);
}

/// Computation of the MixColumns transformation in the fixsliced representation
/// used for rounds i s.t. (i%4) == 2.
fn mixcolumns_2(state: &mut State) {
    let tmp0 = state[7] ^ rotate_rows_1(rotate_columns_1(state[7]));
    let mut tmp2 = state[1];
    state[1] = state[0] ^ tmp0;
    let mut tmp1 = rotate_rows_1(rotate_columns_1(state[0]));
    state[1] ^= tmp1;
    state[0] ^= state[1];
    tmp1 = rotate_rows_1(rotate_columns_1(tmp1));
    tmp1 ^= rotate_rows_1(rotate_columns_1(tmp1));
    state[0] ^= tmp1;
    tmp1 = rotate_rows_1(rotate_columns_1(tmp2));
    state[1] ^= tmp1;
    tmp2 ^= tmp1;
    tmp1 = rotate_rows_1(rotate_columns_1(tmp1));
    tmp1 ^= rotate_rows_1(rotate_columns_1(tmp1));
    state[1] ^= tmp1;
    tmp1 = state[2];
    state[2] = tmp2;
    tmp2 = rotate_rows_1(rotate_columns_1(tmp1));
    tmp1 ^= tmp2;
    state[2] ^= tmp2;
    tmp2 = rotate_rows_1(rotate_columns_1(tmp2));
    tmp2 ^= rotate_rows_1(rotate_columns_1(tmp2));
    state[2] ^= tmp2;
    tmp2 = state[3];
    state[3] = tmp1;
    tmp1 = rotate_rows_1(rotate_columns_1(tmp2));
    tmp2 ^= tmp1;
    state[3] ^= tmp0 ^ tmp1;
    tmp1 = rotate_rows_1(rotate_columns_1(tmp1));
    tmp1 ^= rotate_rows_1(rotate_columns_1(tmp1));
    state[3] ^= tmp1;
    tmp1 = state[4];
    state[4] = tmp0 ^ tmp2;
    tmp2 = rotate_rows_1(rotate_columns_1(tmp1));
    tmp1 ^= tmp2;
    state[4] ^= tmp2;
    tmp2 = rotate_rows_1(rotate_columns_1(tmp2));
    tmp2 ^= rotate_rows_1(rotate_columns_1(tmp2));
    state[4] ^= tmp2;
    tmp2 = state[5];
    state[5] = tmp1;
    tmp1 = rotate_rows_1(rotate_columns_1(tmp2));
    tmp2 ^= tmp1;
    state[5] ^= tmp1;
    tmp1 = rotate_rows_1(rotate_columns_1(tmp1));
    tmp1 ^= rotate_rows_1(rotate_columns_1(tmp1));
    state[5] ^= tmp1;
    tmp1 = state[6];
    state[6] = tmp2;
    tmp2 = rotate_rows_1(rotate_columns_1(tmp1));
    tmp1 ^= tmp2;
    state[6] ^= tmp2;
    tmp2 = rotate_rows_1(rotate_columns_1(tmp2));
    tmp2 ^= rotate_rows_1(rotate_columns_1(tmp2));
    state[6] ^= tmp2;
    tmp2 = rotate_rows_1(rotate_columns_1(state[7]));
    state[7] = tmp1;
    state[7] ^= tmp2;
    tmp2 = rotate_rows_1(rotate_columns_1(tmp2));
    tmp2 ^= rotate_rows_1(rotate_columns_1(tmp2));
    state[7] ^= tmp2;
}

/// Computation of the MixColumns transformation in the fixsliced representation
/// used for rounds i s.t. (i%4) == 3.
///
/// Based on Käsper-Schwabe, similar to https://github.com/Ko-/aes-armcortexm.
#[rustfmt::skip]
fn mixcolumns_3(state: &mut State) {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = (
        state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]
    );
    let (b0, b1, b2, b3, b4, b5, b6, b7) = (
        rotate_rows_1(a0),
        rotate_rows_1(a1),
        rotate_rows_1(a2),
        rotate_rows_1(a3),
        rotate_rows_1(a4),
        rotate_rows_1(a5),
        rotate_rows_1(a6),
        rotate_rows_1(a7),
    );
    let (c0, c1, c2, c3, c4, c5, c6, c7) = (
        a0 ^ b0,
        a1 ^ b1,
        a2 ^ b2,
        a3 ^ b3,
        a4 ^ b4,
        a5 ^ b5,
        a6 ^ b6,
        a7 ^ b7,
    );
    state[0] = b0      ^ c7 ^ rotate_rows_2(c0);
    state[1] = b1 ^ c0 ^ c7 ^ rotate_rows_2(c1);
    state[2] = b2 ^ c1      ^ rotate_rows_2(c2);
    state[3] = b3 ^ c2 ^ c7 ^ rotate_rows_2(c3);
    state[4] = b4 ^ c3 ^ c7 ^ rotate_rows_2(c4);
    state[5] = b5 ^ c4      ^ rotate_rows_2(c5);
    state[6] = b6 ^ c5      ^ rotate_rows_2(c6);
    state[7] = b7 ^ c6      ^ rotate_rows_2(c7);
}

#[inline]
fn delta_swap_1(a: &mut u32, shift: u32, mask: u32) {
    let t = (*a ^ ((*a) >> shift)) & mask;
    *a ^= t ^ (t << shift);
}

#[inline]
fn delta_swap_2(a: &mut u32, b: &mut u32, shift: u32, mask: u32) {
    let t = (*a ^ ((*b) >> shift)) & mask;
    *a ^= t;
    *b ^= t << shift;
}

/// Applies ShiftRows^(-1) on a round key to match the fixsliced representation.
#[inline]
fn inv_shiftrows_1(rkey: &mut [u32]) {
    debug_assert_eq!(rkey.len(), 8);

    for x in rkey.iter_mut() {
        delta_swap_1(x, 4, 0x030f0c00);
        delta_swap_1(x, 2, 0x33003300);
    }
}

/// Applies ShiftRows^(-2) on a round key to match the fixsliced representation.
#[inline]
fn inv_shiftrows_2(rkey: &mut [u32]) {
    debug_assert_eq!(rkey.len(), 8);

    for x in rkey.iter_mut() {
        delta_swap_1(x, 4, 0x0f000f00);
    }
}

/// Applies ShiftRows^(-3) on a round key to match the fixsliced representation.
#[inline]
fn inv_shiftrows_3(rkey: &mut [u32]) {
    debug_assert_eq!(rkey.len(), 8);

    for x in rkey.iter_mut() {
        delta_swap_1(x, 4, 0x0c0f0300);
        delta_swap_1(x, 2, 0x33003300);
    }
}

/// Applies the ShiftRows transformation twice (i.e. SR^2) on the internal state.
#[inline]
fn double_shiftrows(state: &mut State) {
    for x in state.iter_mut() {
        delta_swap_1(x, 4, 0x0f000f00);
    }
}

/// XOR the columns after the S-box during the key schedule round function.
/// Note that the NOT omitted in the S-box calculations have to be applied t
/// ensure output correctness.
///
/// The `idx_xor` parameter refers to the index of the previous round key that is
/// involved in the XOR computation (should be 8 and 16 for AES-128 and AES-256,
/// respectively).
///
/// The `idx_ror` parameter refers to the rotation value, which varies between the
/// different key schedules.
fn xor_columns(rkeys: &mut [u32], offset: usize, idx_xor: usize, idx_ror: u32) {
    sbox_nots(&mut rkeys[offset..(offset + 8)]);

    for i in 0..8 {
        let off_i = offset + i;
        rkeys[off_i] = (rkeys[off_i - idx_xor] ^ ror(rkeys[off_i], idx_ror)) & 0x03030303;
        rkeys[off_i] |= (rkeys[off_i - idx_xor] ^ rkeys[off_i] << 2) & 0x0c0c0c0c;
        rkeys[off_i] |= (rkeys[off_i - idx_xor] ^ rkeys[off_i] << 2) & 0x30303030;
        rkeys[off_i] |= (rkeys[off_i - idx_xor] ^ rkeys[off_i] << 2) & 0xc0c0c0c0;
    }
}

/// Packs two 128-bit input blocks input0, input1 into the 256-bit internal state.
fn packing(output: &mut [u32], input0: &[u8], input1: &[u8]) {
    debug_assert_eq!(output.len(), 8);
    debug_assert_eq!(input0.len(), 16);
    debug_assert_eq!(input1.len(), 16);

    // Bitslicing is a bit index manipulation. 256 bits of data means each bit is positioned at an
    // 8-bit index. AES data is 2 blocks, each one a 4x4 column-major matrix of bytes, so the
    // index is initially ([b]lock, [c]olumn, [r]ow, [p]osition):
    //     b0 c1 c0 r1 r0 p2 p1 p0
    //
    // The desired bitsliced data groups first by bit position, then row, column, block:
    //     p2 p1 p0 r1 r0 c1 c0 b0

    // Interleave the columns on input (note the order of input)
    //     b0 c1 c0 __ __ __ __ __ => c1 c0 b0 __ __ __ __ __
    let mut t0 = LE::read_u32(&input0[0x00..0x04]);
    let mut t2 = LE::read_u32(&input0[0x04..0x08]);
    let mut t4 = LE::read_u32(&input0[0x08..0x0c]);
    let mut t6 = LE::read_u32(&input0[0x0c..0x10]);
    let mut t1 = LE::read_u32(&input1[0x00..0x04]);
    let mut t3 = LE::read_u32(&input1[0x04..0x08]);
    let mut t5 = LE::read_u32(&input1[0x08..0x0c]);
    let mut t7 = LE::read_u32(&input1[0x0c..0x10]);

    // Bit Index Swap 5 <-> 0:
    //     __ __ b0 __ __ __ __ p0 => __ __ p0 __ __ __ __ b0
    let m0 = 0x55555555;
    delta_swap_2(&mut t1, &mut t0, 1, m0);
    delta_swap_2(&mut t3, &mut t2, 1, m0);
    delta_swap_2(&mut t5, &mut t4, 1, m0);
    delta_swap_2(&mut t7, &mut t6, 1, m0);

    // Bit Index Swap 6 <-> 1:
    //     __ c0 __ __ __ __ p1 __ => __ p1 __ __ __ __ c0 __
    let m1 = 0x33333333;
    delta_swap_2(&mut t2, &mut t0, 2, m1);
    delta_swap_2(&mut t3, &mut t1, 2, m1);
    delta_swap_2(&mut t6, &mut t4, 2, m1);
    delta_swap_2(&mut t7, &mut t5, 2, m1);

    // Bit Index Swap 7 <-> 2:
    //     c1 __ __ __ __ p2 __ __ => p2 __ __ __ __ c1 __ __
    let m2 = 0x0f0f0f0f;
    delta_swap_2(&mut t4, &mut t0, 4, m2);
    delta_swap_2(&mut t5, &mut t1, 4, m2);
    delta_swap_2(&mut t6, &mut t2, 4, m2);
    delta_swap_2(&mut t7, &mut t3, 4, m2);

    // Final bitsliced bit index, as desired:
    //     p2 p1 p0 r1 r0 c1 c0 b0
    output[0] = t0;
    output[1] = t1;
    output[2] = t2;
    output[3] = t3;
    output[4] = t4;
    output[5] = t5;
    output[6] = t6;
    output[7] = t7;
}

/// Unpacks the 256-bit internal state into two 128-bit blocks of output.
fn unpacking(input: &mut [u32], output: &mut [Block]) {
    debug_assert_eq!(input.len(), 8);
    debug_assert_eq!(output.len(), 2);

    // Unbitslicing is a bit index manipulation. 256 bits of data means each bit is positioned at
    // an 8-bit index. AES data is 2 blocks, each one a 4x4 column-major matrix of bytes, so the
    // desired index for the output is ([b]lock, [c]olumn, [r]ow, [p]osition):
    //     b0 c1 c0 r1 r0 p2 p1 p0
    //
    // The initially bitsliced data groups first by bit position, then row, column, block:
    //     p2 p1 p0 r1 r0 c1 c0 b0

    let mut t0 = input[0];
    let mut t1 = input[1];
    let mut t2 = input[2];
    let mut t3 = input[3];
    let mut t4 = input[4];
    let mut t5 = input[5];
    let mut t6 = input[6];
    let mut t7 = input[7];

    // TODO: these bit index swaps are identical to those in 'packing'

    // Bit Index Swap 5 <-> 0:
    //     __ __ p0 __ __ __ __ b0 => __ __ b0 __ __ __ __ p0
    let m0 = 0x55555555;
    delta_swap_2(&mut t1, &mut t0, 1, m0);
    delta_swap_2(&mut t3, &mut t2, 1, m0);
    delta_swap_2(&mut t5, &mut t4, 1, m0);
    delta_swap_2(&mut t7, &mut t6, 1, m0);

    // Bit Index Swap 6 <-> 1:
    //     __ p1 __ __ __ __ c0 __ => __ c0 __ __ __ __ p1 __
    let m1 = 0x33333333;
    delta_swap_2(&mut t2, &mut t0, 2, m1);
    delta_swap_2(&mut t3, &mut t1, 2, m1);
    delta_swap_2(&mut t6, &mut t4, 2, m1);
    delta_swap_2(&mut t7, &mut t5, 2, m1);

    // Bit Index Swap 7 <-> 2:
    //     p2 __ __ __ __ c1 __ __ => c1 __ __ __ __ p2 __ __
    let m2 = 0x0f0f0f0f;
    delta_swap_2(&mut t4, &mut t0, 4, m2);
    delta_swap_2(&mut t5, &mut t1, 4, m2);
    delta_swap_2(&mut t6, &mut t2, 4, m2);
    delta_swap_2(&mut t7, &mut t3, 4, m2);

    // De-interleave the columns on output (note the order of output)
    //     c1 c0 b0 __ __ __ __ __ => b0 c1 c0 __ __ __ __ __
    LE::write_u32(&mut output[0][0x00..0x04], t0);
    LE::write_u32(&mut output[0][0x04..0x08], t2);
    LE::write_u32(&mut output[0][0x08..0x0c], t4);
    LE::write_u32(&mut output[0][0x0c..0x10], t6);
    LE::write_u32(&mut output[1][0x00..0x04], t1);
    LE::write_u32(&mut output[1][0x04..0x08], t3);
    LE::write_u32(&mut output[1][0x08..0x0c], t5);
    LE::write_u32(&mut output[1][0x0c..0x10], t7);

    // Final AES bit index, as desired:
    //     b0 c1 c0 r1 r0 p2 p1 p0
}

/// Copy 32-bytes within the provided slice to an 8-byte offset
fn memshift32(buffer: &mut [u32], src_offset: usize) {
    debug_assert_eq!(src_offset % 8, 0);

    let dst_offset = src_offset + 8;
    debug_assert!(dst_offset + 8 <= buffer.len());

    for i in (0..8).rev() {
        buffer[dst_offset + i] = buffer[src_offset + i];
    }
}

/// XOR the round key to the internal state. The round keys are expected to be
/// pre-computed and to be packed in the fixsliced representation.
#[inline]
fn ark(state: &mut State, rkey: &[u32]) {
    debug_assert_eq!(rkey.len(), 8);
    for (a, b) in state.iter_mut().zip(rkey) {
        *a ^= b;
    }
}

#[inline(always)]
fn rcon_bit(state: &mut [u32], bit: usize) {
    state[bit] ^= 0x0000c000;
}

#[inline(always)]
fn ror(x: u32, y: u32) -> u32 {
    x.rotate_right(y)
}

#[inline(always)]
fn ror_distance(rows: u32, cols: u32) -> u32 {
    (rows << 3) + (cols << 1)
}

#[inline]
fn rotate_columns_1(x: u32) -> u32 {
    ((x >> 6) & 0x03030303) | ((x & 0x3f3f3f3f) << 2)
}

#[inline]
fn rotate_columns_2(x: u32) -> u32 {
    ((x >> 4) & 0x0f0f0f0f) | ((x & 0x0f0f0f0f) << 4)
}

#[inline]
fn rotate_columns_3(x: u32) -> u32 {
    ((x >> 2) & 0x3f3f3f3f) | ((x & 0x03030303) << 6)
}

#[inline(always)]
fn rotate_rows_1(x: u32) -> u32 {
    ror(x, ror_distance(1, 0))
}

#[inline(always)]
fn rotate_rows_2(x: u32) -> u32 {
    ror(x, ror_distance(2, 0))
}
