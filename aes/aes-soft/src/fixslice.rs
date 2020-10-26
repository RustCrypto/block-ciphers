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
use cipher::{
    consts::{U16, U24, U32},
    generic_array::GenericArray,
};
use core::convert::TryInto;

/// AES-128 round keys
pub(crate) type FixsliceKeys128 = [u32; 88];

/// AES-192 round keys
pub(crate) type FixsliceKeys192 = [u32; 104];

/// AES-256 round keys
pub(crate) type FixsliceKeys256 = [u32; 120];

/// 256-bit internal state
type State = [u32; 8];

/// Fully bitsliced AES-128 key schedule to match the fully-fixsliced
/// representation.
pub(crate) fn aes128_key_schedule(key: &GenericArray<u8, U16>) -> FixsliceKeys128 {
    // TODO(tarcieri): use `::default()` after MSRV 1.47+
    let mut rkeys = [0u32; 88];

    // Pack the keys into the bitsliced state
    packing(&mut rkeys[..8], key, key);
    memshift32(&mut rkeys, 0);
    sbox(&mut rkeys[8..16]);

    rkeys[15] ^= 0x00000300; // 1st rconst
    xor_columns(&mut rkeys, 8, 8, 2); // Rotword and XOR between the columns
    memshift32(&mut rkeys, 8);
    sbox(&mut rkeys[16..24]);

    rkeys[22] ^= 0x00000300; // 2nd rconst
    xor_columns(&mut rkeys, 16, 8, 2); // Rotword and XOR between the columns
    inv_shiftrows_1(&mut rkeys[8..16]); // to match fixslicing
    memshift32(&mut rkeys, 16);
    sbox(&mut rkeys[24..32]);

    rkeys[29] ^= 0x00000300; // 3rd rconst
    xor_columns(&mut rkeys, 24, 8, 2); // Rotword and XOR between the columns
    inv_shiftrows_2(&mut rkeys[16..24]); // to match fixslicing
    memshift32(&mut rkeys, 24);
    sbox(&mut rkeys[32..40]);

    rkeys[36] ^= 0x00000300; // 4th rconst
    xor_columns(&mut rkeys, 32, 8, 2); // Rotword and XOR between the columns
    inv_shiftrows_3(&mut rkeys[24..32]); // to match fixslicing
    memshift32(&mut rkeys, 32);
    sbox(&mut rkeys[40..48]);

    rkeys[43] ^= 0x00000300; // 5th rconst
    xor_columns(&mut rkeys, 40, 8, 2); // Rotword and XOR between the columns
    memshift32(&mut rkeys, 40);
    sbox(&mut rkeys[48..56]);

    rkeys[50] ^= 0x00000300; // 6th rconst
    xor_columns(&mut rkeys, 48, 8, 2); // Rotword and XOR between the columns
    inv_shiftrows_1(&mut rkeys[40..48]); // to match fixslicing
    memshift32(&mut rkeys, 48);
    sbox(&mut rkeys[56..64]);

    rkeys[57] ^= 0x00000300; // 7th rconst
    xor_columns(&mut rkeys, 56, 8, 2); // Rotword and XOR between the columns
    inv_shiftrows_2(&mut rkeys[48..56]); // to match fixslicing
    memshift32(&mut rkeys, 56);
    sbox(&mut rkeys[64..72]);

    rkeys[64] ^= 0x00000300; // 8th rconst
    xor_columns(&mut rkeys, 64, 8, 2); // Rotword and XOR between the columns
    inv_shiftrows_3(&mut rkeys[56..64]); // to match fixslicing
    memshift32(&mut rkeys, 64);
    sbox(&mut rkeys[72..80]);

    rkeys[79] ^= 0x00000300; // 9th rconst
    rkeys[78] ^= 0x00000300; // 9th rconst
    rkeys[76] ^= 0x00000300; // 9th rconst
    rkeys[75] ^= 0x00000300; // 9th rconst
    xor_columns(&mut rkeys, 72, 8, 2); // Rotword and XOR between the columns
    memshift32(&mut rkeys, 72);
    sbox(&mut rkeys[80..]);

    rkeys[86] ^= 0x00000300; // 10th rconst
    rkeys[85] ^= 0x00000300; // 10th rconst
    rkeys[83] ^= 0x00000300; // 10th rconst
    rkeys[82] ^= 0x00000300; // 10th rconst
    xor_columns(&mut rkeys, 80, 8, 2); // Rotword and XOR between the columns
    inv_shiftrows_1(&mut rkeys[72..80]);

    // Bitwise NOT to speed up SBox calculations
    for i in 1..11 {
        rkeys[i * 8 + 1] ^= 0xffffffff;
        rkeys[i * 8 + 2] ^= 0xffffffff;
        rkeys[i * 8 + 6] ^= 0xffffffff;
        rkeys[i * 8 + 7] ^= 0xffffffff;
    }

    rkeys
}

/// Fully bitsliced AES-192 key schedule to match the fully-fixsliced
/// representation.
pub(crate) fn aes192_key_schedule(key: &GenericArray<u8, U24>) -> FixsliceKeys192 {
    // TODO(tarcieri): use `::default()` after MSRV 1.47+
    let mut rkeys = [0u32; 104];
    let mut tmp = [0u32; 8];

    // Pack the keys into the bitsliced state
    packing(&mut rkeys[..8], &key[..16], &key[..16]);
    packing(&mut tmp, &key[8..], &key[8..]);

    let mut rcon = 8;
    let mut rk_off = 8;

    loop {
        for i in 0..8 {
            rkeys[rk_off + i] =
                (0xf0f0f0f0 & (tmp[i] << 4)) | (0x0f0f0f0f & (rkeys[(rk_off - 8) + i] >> 4));
        }

        sbox(&mut tmp);

        // NOT operations that are omitted in S-box
        tmp[1] ^= 0xffffffff;
        tmp[2] ^= 0xffffffff;
        tmp[6] ^= 0xffffffff;
        tmp[7] ^= 0xffffffff;

        rcon -= 1;
        tmp[rcon] ^= 0x00000300;

        for i in 0..8 {
            let mut ti = rkeys[rk_off + i];
            ti ^= 0x0c0c0c0c & ror(tmp[i], 8 - 2);
            ti ^= 0x03030303 & (ti >> 2);
            tmp[i] = ti;
        }
        rkeys[rk_off..(rk_off + 8)].copy_from_slice(&tmp);
        rk_off += 8;

        for i in 0..8 {
            let ui = tmp[i];
            let mut ti = (0xf0f0f0f0 & (rkeys[(rk_off - 16) + i] << 4)) | (0x0f0f0f0f & (ui >> 4));
            ti ^= 0xc0c0c0c0 & (ui << 6);
            ti ^= 0x30303030 & (ti >> 2);
            ti ^= 0x0c0c0c0c & (ti >> 2);
            ti ^= 0x03030303 & (ti >> 2);
            tmp[i] = ti;
        }
        rkeys[rk_off..(rk_off + 8)].copy_from_slice(&tmp);
        rk_off += 8;

        sbox(&mut tmp);

        // NOT operations that are omitted in S-box
        tmp[1] ^= 0xffffffff;
        tmp[2] ^= 0xffffffff;
        tmp[6] ^= 0xffffffff;
        tmp[7] ^= 0xffffffff;

        rcon -= 1;
        tmp[rcon] ^= 0x00000300;

        for i in 0..8 {
            let mut ti = (0xf0f0f0f0 & (rkeys[(rk_off - 16) + i] << 4))
                | (0x0f0f0f0f & (rkeys[(rk_off - 8) + i] >> 4));
            ti ^= 0xc0c0c0c0 & ror(tmp[i], 8 - 6);
            ti ^= 0x30303030 & (ti >> 2);
            ti ^= 0x0c0c0c0c & (ti >> 2);
            ti ^= 0x03030303 & (ti >> 2);
            rkeys[rk_off + i] = ti;
        }
        rk_off += 8;

        if rcon == 0 {
            break;
        }

        for i in 0..8 {
            let ui = rkeys[(rk_off - 8) + i];
            let mut ti = rkeys[(rk_off - 16) + i];
            ti ^= 0x0c0c0c0c & (ui << 2);
            ti ^= 0x03030303 & (ti >> 2);
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
        rkeys[i * 8 + 1] ^= 0xffffffff;
        rkeys[i * 8 + 2] ^= 0xffffffff;
        rkeys[i * 8 + 6] ^= 0xffffffff;
        rkeys[i * 8 + 7] ^= 0xffffffff;
    }

    rkeys
}

/// Fully bitsliced AES-256 key schedule to match the fully-fixsliced
/// representation.
pub(crate) fn aes256_key_schedule(key: &GenericArray<u8, U32>) -> FixsliceKeys256 {
    // TODO(tarcieri): use `::default()` after MSRV 1.47+
    let mut rkeys = [0u32; 120];

    // Pack the keys into the bitsliced state
    packing(&mut rkeys[..8], &key[..16], &key[..16]);
    packing(&mut rkeys[8..16], &key[16..], &key[16..]);
    memshift32(&mut rkeys, 8);
    sbox(&mut rkeys[16..24]);

    rkeys[23] ^= 0x00000300; // 1st rconst
    xor_columns(&mut rkeys, 16, 16, 2); // Rotword and XOR between the columns
    memshift32(&mut rkeys, 16);
    sbox(&mut rkeys[24..32]);
    xor_columns(&mut rkeys, 24, 16, 26); // XOR between the columns
    inv_shiftrows_1(&mut rkeys[8..16]); // to match fixslicing
    memshift32(&mut rkeys, 24);
    sbox(&mut rkeys[32..40]);

    rkeys[38] ^= 0x00000300; // 2nd rconst
    xor_columns(&mut rkeys, 32, 16, 2); // Rotword and XOR between the columns
    inv_shiftrows_2(&mut rkeys[16..24]); // to match fixslicing
    memshift32(&mut rkeys, 32);
    sbox(&mut rkeys[40..48]);
    xor_columns(&mut rkeys, 40, 16, 26); // XOR between the columns
    inv_shiftrows_3(&mut rkeys[24..32]); // to match fixslicing
    memshift32(&mut rkeys, 40);
    sbox(&mut rkeys[48..56]);

    rkeys[53] ^= 0x00000300; // 3rd rconst
    xor_columns(&mut rkeys, 48, 16, 2); // Rotword and XOR between the columns
    memshift32(&mut rkeys, 48);
    sbox(&mut rkeys[56..64]);
    xor_columns(&mut rkeys, 56, 16, 26); // XOR between the columns
    inv_shiftrows_1(&mut rkeys[40..48]); // to match fixslicing
    memshift32(&mut rkeys, 56);
    sbox(&mut rkeys[64..72]);

    rkeys[68] ^= 0x00000300; // 4th rconst
    xor_columns(&mut rkeys, 64, 16, 2); // Rotword and XOR between the columns
    inv_shiftrows_2(&mut rkeys[48..56]); // to match fixslicing
    memshift32(&mut rkeys, 64);
    sbox(&mut rkeys[72..80]);
    xor_columns(&mut rkeys, 72, 16, 26); // XOR between the columns
    inv_shiftrows_3(&mut rkeys[56..64]); // to match fixslicing
    memshift32(&mut rkeys, 72);
    sbox(&mut rkeys[80..88]);

    rkeys[83] ^= 0x00000300; // 5th rconst
    xor_columns(&mut rkeys, 80, 16, 2); // Rotword and XOR between the columns
    memshift32(&mut rkeys, 80);
    sbox(&mut rkeys[88..96]);
    xor_columns(&mut rkeys, 88, 16, 26); // XOR between the columns
    inv_shiftrows_1(&mut rkeys[72..80]); // to match fixslicing
    memshift32(&mut rkeys, 88);
    sbox(&mut rkeys[96..104]);

    rkeys[98] ^= 0x00000300; // 6th rconst
    xor_columns(&mut rkeys, 96, 16, 2); // Rotword and XOR between the columns
    inv_shiftrows_2(&mut rkeys[80..88]); // to match fixslicing
    memshift32(&mut rkeys, 96);
    sbox(&mut rkeys[104..112]);
    xor_columns(&mut rkeys, 104, 16, 26); // XOR between the columns
    inv_shiftrows_3(&mut rkeys[88..96]); // to match fixslicing
    memshift32(&mut rkeys, 104);
    sbox(&mut rkeys[112..]);

    rkeys[113] ^= 0x00000300; // 7th rconst
    xor_columns(&mut rkeys, 112, 16, 2); // Rotword and XOR between the columns
    inv_shiftrows_1(&mut rkeys[104..112]); // to match fixslicing

    // Bitwise NOT to speed up SBox calculations
    for i in 1..15 {
        rkeys[i * 8 + 1] ^= 0xffffffff;
        rkeys[i * 8 + 2] ^= 0xffffffff;
        rkeys[i * 8 + 6] ^= 0xffffffff;
        rkeys[i * 8 + 7] ^= 0xffffffff;
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
    packing(&mut state, blocks[0].as_ref(), blocks[1].as_ref());
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

    let mut t0 = state[3] ^ state[5];
    let mut t1 = state[0] ^ state[6];
    let mut t2 = t1 ^ t0;
    let mut t3 = state[4] ^ t2;
    let mut t4 = t3 ^ state[5];
    let mut t5 = t2 & t4;
    let mut t6 = t4 ^ state[7];
    let mut t7 = t3 ^ state[1];
    let t8 = state[0] ^ state[3];
    let t9 = t7 ^ t8;
    let mut t10 = t8 & t9;
    let mut t11 = state[7] ^ t9;
    let mut t12 = state[0] ^ state[5];
    let mut t13 = state[1] ^ state[2];
    let mut t14 = t4 ^ t13;
    let mut t15 = t14 ^ t9;
    let mut t16 = t0 & t15;
    let mut t17 = t16 ^ t10;
    state[1] = t14 ^ t12;
    state[2] = t12 & t14;
    state[2] ^= t10;
    state[4] = t13 ^ t9;
    state[5] = t1 ^ state[4];
    t3 = t1 & state[4];
    t10 = state[0] ^ state[4];
    t13 ^= state[7];
    state[3] ^= t13;
    t16 = state[3] & state[7];
    t16 ^= t5;
    t16 ^= state[2];
    state[1] ^= t16;
    state[0] ^= t13;
    t16 = state[0] & t11;
    t16 ^= t3;
    state[2] ^= t16;
    state[2] ^= t10;
    state[6] ^= t13;
    t10 = state[6] & t13;
    t3 ^= t10;
    t3 ^= t17;
    state[5] ^= t3;
    t3 = state[6] ^ t12;
    t10 = t3 & t6;
    t5 ^= t10;
    t5 ^= t7;
    t5 ^= t17;
    t7 = t5 & state[5];
    t10 = state[2] ^ t7;
    t7 ^= state[1];
    t5 ^= state[1];
    t16 = t5 & t10;
    state[1] ^= t16;
    t17 = state[1] & state[0];
    t11 &= state[1];
    t16 = state[5] ^ state[2];
    t7 &= t16;
    t7 ^= state[2];
    t16 = t10 ^ t7;
    state[2] &= t16;
    t10 ^= state[2];
    t10 &= state[1];
    t5 ^= t10;
    t10 = state[1] ^ t5;
    state[4] &= t10;
    t11 ^= state[4];
    t1 &= t10;
    state[6] &= t5;
    t10 = t5 & t13;
    state[4] ^= t10;
    state[5] ^= t7;
    state[2] ^= state[5];
    state[5] = t5 ^ state[2];
    t5 = state[5] & t14;
    t10 = state[5] & t12;
    t12 = t7 ^ state[2];
    t4 &= t12;
    t2 &= t12;
    t3 &= state[2];
    state[2] &= t6;
    state[2] ^= t4;
    t13 = state[4] ^ state[2];
    state[3] &= t7;
    state[1] ^= t7;
    state[5] ^= state[1];
    t6 = state[5] & t15;
    state[4] ^= t6;
    t0 &= state[5];
    state[5] = state[1] & t9;
    state[5] ^= state[4];
    state[1] &= t8;
    t6 = state[1] ^ state[5];
    t0 ^= state[1];
    state[1] = t3 ^ t0;
    t15 = state[1] ^ state[3];
    t2 ^= state[1];
    state[0] = t2 ^ state[5];
    state[3] = t2 ^ t13;
    state[1] = state[3] ^ state[5];
    //state[1] ^= 0xffffffff;
    t0 ^= state[6];
    state[5] = t7 & state[7];
    t14 = t4 ^ state[5];
    state[6] = t1 ^ t14;
    state[6] ^= t5;
    state[6] ^= state[4];
    state[2] = t17 ^ state[6];
    state[5] = t15 ^ state[2];
    state[2] ^= t6;
    state[2] ^= t10;
    //state[2] ^= 0xffffffff;
    t14 ^= t11;
    t0 ^= t14;
    state[6] ^= t0;
    //state[6] ^= 0xffffffff;
    state[7] = t1 ^ t0;
    //state[7] ^= 0xffffffff;
    state[4] = t14 ^ state[3];
}

/// Computation of the MixColumns transformation in the fixsliced representation
/// used for rounds i s.t. (i%4) == 0.
fn mixcolumns_0(state: &mut State) {
    let mut tmp3 = ror(byte_ror_6(state[0]), 8);
    let tmp0 = state[0] ^ tmp3;
    let mut tmp2 = state[6];
    state[6] = state[7] ^ tmp0;
    let mut tmp1 = ror(byte_ror_6(state[7]), 8);
    state[6] ^= tmp1;
    state[7] ^= state[6];
    tmp1 = ror(byte_ror_6(tmp1), 8);
    tmp1 ^= ror(byte_ror_6(tmp1), 8);
    state[7] ^= tmp1;
    tmp1 = ror(byte_ror_6(tmp2), 8);
    state[6] ^= tmp1;
    tmp2 ^= tmp1;
    tmp1 = ror(byte_ror_6(tmp1), 8);
    tmp1 ^= ror(byte_ror_6(tmp1), 8);
    state[6] ^= tmp1;
    tmp1 = state[5];
    state[5] = tmp2;
    tmp2 = ror(byte_ror_6(tmp1), 8);
    tmp1 ^= tmp2;
    state[5] ^= tmp2;
    tmp2 = ror(byte_ror_6(tmp2), 8);
    tmp2 ^= ror(byte_ror_6(tmp2), 8);
    state[5] ^= tmp2;
    tmp2 = state[4];
    state[4] = tmp1;
    tmp1 = ror(byte_ror_6(tmp2), 8);
    tmp2 ^= tmp1;
    state[4] ^= tmp0 ^ tmp1;
    tmp1 = ror(byte_ror_6(tmp1), 8);
    tmp1 ^= ror(byte_ror_6(tmp1), 8);
    state[4] ^= tmp1;
    tmp1 = state[3];
    state[3] = tmp0 ^ tmp2;
    tmp2 = ror(byte_ror_6(tmp1), 8);
    tmp1 ^= tmp2;
    state[3] ^= tmp2;
    tmp2 = ror(byte_ror_6(tmp2), 8);
    tmp2 ^= ror(byte_ror_6(tmp2), 8);
    state[3] ^= tmp2;
    tmp2 = state[2];
    state[2] = tmp1;
    tmp1 = ror(byte_ror_6(tmp2), 8);
    tmp2 ^= tmp1;
    state[2] ^= tmp1;
    tmp1 = ror(byte_ror_6(tmp1), 8);
    tmp1 ^= ror(byte_ror_6(tmp1), 8);
    state[2] ^= tmp1;
    tmp1 = state[1];
    state[1] = tmp2;
    tmp2 = ror(byte_ror_6(tmp1), 8);
    tmp1 ^= tmp2;
    state[1] ^= tmp2;
    tmp2 = ror(byte_ror_6(tmp2), 8);
    tmp2 ^= ror(byte_ror_6(tmp2), 8);
    state[1] ^= tmp2;
    state[0] = tmp1;
    state[0] ^= tmp3;
    tmp3 = ror(byte_ror_6(tmp3), 8);
    tmp3 ^= ror(byte_ror_6(tmp3), 8);
    state[0] ^= tmp3;
}

/// Computation of the MixColumns transformation in the fixsliced representation
/// used for round i s.t. (i%4) == 1.
fn mixcolumns_1(state: &mut State) {
    let tmp0 = state[0] ^ ror(byte_ror_4(state[0]), 8);
    let mut tmp1 = state[7] ^ ror(byte_ror_4(state[7]), 8);
    let mut tmp2 = state[6];
    state[6] = tmp1 ^ tmp0;
    state[7] ^= state[6] ^ ror(tmp1, 16);
    tmp1 = ror(byte_ror_4(tmp2), 8);
    state[6] ^= tmp1;
    tmp1 ^= tmp2;
    state[6] ^= ror(tmp1, 16);
    tmp2 = state[5];
    state[5] = tmp1;
    tmp1 = ror(byte_ror_4(tmp2), 8);
    state[5] ^= tmp1;
    tmp1 ^= tmp2;
    state[5] ^= ror(tmp1, 16);
    tmp2 = state[4];
    state[4] = tmp1 ^ tmp0;
    tmp1 = ror(byte_ror_4(tmp2), 8);
    state[4] ^= tmp1;
    tmp1 ^= tmp2;
    state[4] ^= ror(tmp1, 16);
    tmp2 = state[3];
    state[3] = tmp1 ^ tmp0;
    tmp1 = ror(byte_ror_4(tmp2), 8);
    state[3] ^= tmp1;
    tmp1 ^= tmp2;
    state[3] ^= ror(tmp1, 16);
    tmp2 = state[2];
    state[2] = tmp1;
    tmp1 = ror(byte_ror_4(tmp2), 8);
    state[2] ^= tmp1;
    tmp1 ^= tmp2;
    state[2] ^= ror(tmp1, 16);
    tmp2 = state[1];
    state[1] = tmp1;
    tmp1 = ror(byte_ror_4(tmp2), 8);
    state[1] ^= tmp1;
    tmp1 ^= tmp2;
    state[1] ^= ror(tmp1, 16);
    tmp2 = state[0];
    state[0] = tmp1;
    tmp1 = ror(byte_ror_4(tmp2), 8);
    state[0] ^= tmp1;
    tmp1 ^= tmp2;
    state[0] ^= ror(tmp1, 16);
}

/// Computation of the MixColumns transformation in the fixsliced representation
/// used for rounds i s.t. (i%4) == 2.
fn mixcolumns_2(state: &mut State) {
    let tmp0 = state[0] ^ ror(byte_ror_2(state[0]), 8);
    let mut tmp2 = state[6];
    state[6] = state[7] ^ tmp0;
    let mut tmp1 = ror(byte_ror_2(state[7]), 8);
    state[6] ^= tmp1;
    state[7] ^= state[6];
    tmp1 = ror(byte_ror_2(tmp1), 8);
    tmp1 ^= ror(byte_ror_2(tmp1), 8);
    state[7] ^= tmp1;
    tmp1 = ror(byte_ror_2(tmp2), 8);
    state[6] ^= tmp1;
    tmp2 ^= tmp1;
    tmp1 = ror(byte_ror_2(tmp1), 8);
    tmp1 ^= ror(byte_ror_2(tmp1), 8);
    state[6] ^= tmp1;
    tmp1 = state[5];
    state[5] = tmp2;
    tmp2 = ror(byte_ror_2(tmp1), 8);
    tmp1 ^= tmp2;
    state[5] ^= tmp2;
    tmp2 = ror(byte_ror_2(tmp2), 8);
    tmp2 ^= ror(byte_ror_2(tmp2), 8);
    state[5] ^= tmp2;
    tmp2 = state[4];
    state[4] = tmp1;
    tmp1 = ror(byte_ror_2(tmp2), 8);
    tmp2 ^= tmp1;
    state[4] ^= tmp0 ^ tmp1;
    tmp1 = ror(byte_ror_2(tmp1), 8);
    tmp1 ^= ror(byte_ror_2(tmp1), 8);
    state[4] ^= tmp1;
    tmp1 = state[3];
    state[3] = tmp0 ^ tmp2;
    tmp2 = ror(byte_ror_2(tmp1), 8);
    tmp1 ^= tmp2;
    state[3] ^= tmp2;
    tmp2 = ror(byte_ror_2(tmp2), 8);
    tmp2 ^= ror(byte_ror_2(tmp2), 8);
    state[3] ^= tmp2;
    tmp2 = state[2];
    state[2] = tmp1;
    tmp1 = ror(byte_ror_2(tmp2), 8);
    tmp2 ^= tmp1;
    state[2] ^= tmp1;
    tmp1 = ror(byte_ror_2(tmp1), 8);
    tmp1 ^= ror(byte_ror_2(tmp1), 8);
    state[2] ^= tmp1;
    tmp1 = state[1];
    state[1] = tmp2;
    tmp2 = ror(byte_ror_2(tmp1), 8);
    tmp1 ^= tmp2;
    state[1] ^= tmp2;
    tmp2 = ror(byte_ror_2(tmp2), 8);
    tmp2 ^= ror(byte_ror_2(tmp2), 8);
    state[1] ^= tmp2;
    tmp2 = ror(byte_ror_2(state[0]), 8);
    state[0] = tmp1;
    state[0] ^= tmp2;
    tmp2 = ror(byte_ror_2(tmp2), 8);
    tmp2 ^= ror(byte_ror_2(tmp2), 8);
    state[0] ^= tmp2;
}

/// Computation of the MixColumns transformation in the fixsliced representation
/// used for rounds i s.t. (i%4) == 3.
///
/// Based on Käsper-Schwabe, similar to https://github.com/Ko-/aes-armcortexm.
fn mixcolumns_3(state: &mut State) {
    let mut tmp0 = state[7] ^ ror(state[7], 8);
    let tmp2 = state[0] ^ ror(state[0], 8);
    state[7] = tmp2 ^ ror(state[7], 8) ^ ror(tmp0, 16);
    let mut tmp1 = state[6] ^ ror(state[6], 8);
    state[6] = tmp0 ^ tmp2 ^ ror(state[6], 8) ^ ror(tmp1, 16);
    tmp0 = state[5] ^ ror(state[5], 8);
    state[5] = tmp1 ^ ror(state[5], 8) ^ ror(tmp0, 16);
    tmp1 = state[4] ^ ror(state[4], 8);
    state[4] = tmp0 ^ tmp2 ^ ror(state[4], 8) ^ ror(tmp1, 16);
    tmp0 = state[3] ^ ror(state[3], 8);
    state[3] = tmp1 ^ tmp2 ^ ror(state[3], 8) ^ ror(tmp0, 16);
    tmp1 = state[2] ^ ror(state[2], 8);
    state[2] = tmp0 ^ ror(state[2], 8) ^ ror(tmp1, 16);
    tmp0 = state[1] ^ ror(state[1], 8);
    state[1] = tmp1 ^ ror(state[1], 8) ^ ror(tmp0, 16);
    state[0] = tmp0 ^ ror(state[0], 8) ^ ror(tmp2, 16);
}

/// SWAPMOVE
macro_rules! swapmove {
    ($a:expr, $b:expr, $mask:expr, $n:expr) => {
        let tmp = ($b ^ ($a >> $n)) & $mask;
        $b ^= tmp;
        $a ^= tmp << $n;
    };
}

/// Applies ShiftRows^(-1) on a round key to match the fixsliced representation.
#[inline]
fn inv_shiftrows_1(rkey: &mut [u32]) {
    debug_assert_eq!(rkey.len(), 8);

    for x in rkey.iter_mut() {
        swapmove!(*x, *x, 0x0c0f0300, 4);
        swapmove!(*x, *x, 0x33003300, 2);
    }
}

/// Applies ShiftRows^(-2) on a round key to match the fixsliced representation.
#[inline]
fn inv_shiftrows_2(rkey: &mut [u32]) {
    debug_assert_eq!(rkey.len(), 8);

    for x in rkey.iter_mut() {
        swapmove!(*x, *x, 0x0f000f00, 4);
    }
}

/// Applies ShiftRows^(-3) on a round key to match the fixsliced representation.
#[inline]
fn inv_shiftrows_3(rkey: &mut [u32]) {
    debug_assert_eq!(rkey.len(), 8);

    for x in rkey.iter_mut() {
        swapmove!(*x, *x, 0x030f0c00, 4);
        swapmove!(*x, *x, 0x33003300, 2);
    }
}

/// Applies the ShiftRows transformation twice (i.e. SR^2) on the internal state.
#[inline]
fn double_shiftrows(state: &mut State) {
    for x in state.iter_mut() {
        swapmove!(*x, *x, 0x0f000f00, 4);
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
/// The `idx_ror` parameter refers to the rotation value. When a Rotword is applied
/// the value should be 2, 26 otherwise.
fn xor_columns(rkeys: &mut [u32], offset: usize, idx_xor: usize, idx_ror: usize) {
    // NOT operations that are omitted in S-box
    rkeys[offset + 1] ^= 0xffffffff;
    rkeys[offset + 2] ^= 0xffffffff;
    rkeys[offset + 6] ^= 0xffffffff;
    rkeys[offset + 7] ^= 0xffffffff;

    for i in 0..8 {
        let off_i = offset + i;
        rkeys[off_i] = (rkeys[off_i - idx_xor] ^ ror(rkeys[off_i], idx_ror)) & 0xc0c0c0c0;
        rkeys[off_i] |= (rkeys[off_i - idx_xor] ^ rkeys[off_i] >> 2) & 0x30303030;
        rkeys[off_i] |= (rkeys[off_i - idx_xor] ^ rkeys[off_i] >> 2) & 0x0c0c0c0c;
        rkeys[off_i] |= (rkeys[off_i - idx_xor] ^ rkeys[off_i] >> 2) & 0x03030303;
    }
}

/// Packs two 128-bit input blocs in0, in1 into the 256-bit internal state out
/// where the bits are packed as follows:
///
/// ```text
/// out[0] = b_24 b_56 b_88 b_120 || ... || b_0 b_32 b_64 b_96
/// out[1] = b_25 b_57 b_89 b_121 || ... || b_1 b_33 b_65 b_97
/// out[2] = b_26 b_58 b_90 b_122 || ... || b_2 b_34 b_66 b_98
/// out[3] = b_27 b_59 b_91 b_123 || ... || b_3 b_35 b_67 b_99
/// out[4] = b_28 b_60 b_92 b_124 || ... || b_4 b_36 b_68 b_100
/// out[5] = b_29 b_61 b_93 b_125 || ... || b_5 b_37 b_69 b_101
/// out[6] = b_30 b_62 b_94 b_126 || ... || b_6 b_38 b_70 b_102
/// out[7] = b_31 b_63 b_95 b_127 || ... || b_7 b_39 b_71 b_103
/// ```
fn packing(output: &mut [u32], input0: &[u8], input1: &[u8]) {
    debug_assert_eq!(output.len(), 8);
    debug_assert_eq!(input0.len(), 16);
    debug_assert_eq!(input1.len(), 16);

    for (n, (i0, i1)) in input0.chunks(4).zip(input1.chunks(4)).enumerate() {
        output[n * 2] = u32::from_le_bytes(i0.try_into().unwrap());
        output[(n * 2) + 1] = u32::from_le_bytes(i1.try_into().unwrap());
    }

    swapmove!(output[1], output[0], 0x55555555, 1);
    swapmove!(output[3], output[2], 0x55555555, 1);
    swapmove!(output[5], output[4], 0x55555555, 1);
    swapmove!(output[7], output[6], 0x55555555, 1);
    swapmove!(output[2], output[0], 0x33333333, 2);
    swapmove!(output[3], output[1], 0x33333333, 2);
    swapmove!(output[6], output[4], 0x33333333, 2);
    swapmove!(output[7], output[5], 0x33333333, 2);
    swapmove!(output[4], output[0], 0x0f0f0f0f, 4);
    swapmove!(output[5], output[1], 0x0f0f0f0f, 4);
    swapmove!(output[6], output[2], 0x0f0f0f0f, 4);
    swapmove!(output[7], output[3], 0x0f0f0f0f, 4);
}

/// Unpacks the 256-bit internal state in two 128-bit blocs out0, out1.
fn unpacking(input: &mut [u32], output: &mut [Block]) {
    debug_assert_eq!(input.len(), 8);
    debug_assert_eq!(output.len(), 2);

    swapmove!(input[4], input[0], 0x0f0f0f0f, 4);
    swapmove!(input[5], input[1], 0x0f0f0f0f, 4);
    swapmove!(input[6], input[2], 0x0f0f0f0f, 4);
    swapmove!(input[7], input[3], 0x0f0f0f0f, 4);
    swapmove!(input[2], input[0], 0x33333333, 2);
    swapmove!(input[3], input[1], 0x33333333, 2);
    swapmove!(input[6], input[4], 0x33333333, 2);
    swapmove!(input[7], input[5], 0x33333333, 2);
    swapmove!(input[1], input[0], 0x55555555, 1);
    swapmove!(input[3], input[2], 0x55555555, 1);
    swapmove!(input[5], input[4], 0x55555555, 1);
    swapmove!(input[7], input[6], 0x55555555, 1);

    let (output0, output1) = output.split_at_mut(1);

    for (n, (o0, o1)) in output0[0]
        .chunks_mut(4)
        .zip(output1[0].chunks_mut(4))
        .enumerate()
    {
        o0.copy_from_slice(&input[n * 2].to_le_bytes());
        o1.copy_from_slice(&input[(n * 2) + 1].to_le_bytes());
    }
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

/// ROR
#[inline]
fn ror(x: u32, y: usize) -> u32 {
    (x >> y) | (x << (32 - y))
}

/// BYTE_ROR_6
#[inline]
fn byte_ror_6(x: u32) -> u32 {
    ((x >> 6) & 0x03030303) | ((x & 0x3f3f3f3f) << 2)
}

/// BYTE_ROR_4
#[inline]
fn byte_ror_4(x: u32) -> u32 {
    ((x >> 4) & 0x0f0f0f0f) | ((x & 0x0f0f0f0f) << 4)
}

/// BYTE_ROR_2
#[inline]
fn byte_ror_2(x: u32) -> u32 {
    ((x >> 2) & 0x3f3f3f3f) | ((x & 0x03030303) << 6)
}
