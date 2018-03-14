use core::ops::{BitAnd, BitXor, Not};
use byte_tools::{read_u32v_le, write_u32_le};
use simd::u32x4;
use consts::U32X4_1;

// This trait defines all of the operations needed for a type to be processed as part of an AES
// encryption or decryption operation.
pub trait AesOps {
    fn sub_bytes(self) -> Self;
    fn inv_sub_bytes(self) -> Self;
    fn shift_rows(self) -> Self;
    fn inv_shift_rows(self) -> Self;
    fn mix_columns(self) -> Self;
    fn inv_mix_columns(self) -> Self;
    fn add_round_key(self, rk: &Self) -> Self;
}

pub fn encrypt_core<S: AesOps + Copy>(state: &S, sk: &[S]) -> S {
    // Round 0 - add round key
    let mut tmp = state.add_round_key(&sk[0]);

    // Remaining rounds (except last round)
    for i in 1..sk.len() - 1 {
        tmp = tmp.sub_bytes();
        tmp = tmp.shift_rows();
        tmp = tmp.mix_columns();
        tmp = tmp.add_round_key(&sk[i]);
    }

    // Last round
    tmp = tmp.sub_bytes();
    tmp = tmp.shift_rows();
    tmp = tmp.add_round_key(&sk[sk.len() - 1]);

    tmp
}

pub fn decrypt_core<S: AesOps + Copy>(state: &S, sk: &[S]) -> S {
    // Round 0 - add round key
    let mut tmp = state.add_round_key(&sk[sk.len() - 1]);

    // Remaining rounds (except last round)
    for i in 1..sk.len() - 1 {
        tmp = tmp.inv_sub_bytes();
        tmp = tmp.inv_shift_rows();
        tmp = tmp.inv_mix_columns();
        tmp = tmp.add_round_key(&sk[sk.len() - 1 - i]);
    }

    // Last round
    tmp = tmp.inv_sub_bytes();
    tmp = tmp.inv_shift_rows();
    tmp = tmp.add_round_key(&sk[0]);

    tmp
}

#[derive(Clone, Copy)]
pub struct Bs8State<T>(pub T, pub T, pub T, pub T, pub T, pub T, pub T, pub T);

impl<T: Copy> Bs8State<T> {
    fn split(self) -> (Bs4State<T>, Bs4State<T>) {
        let Bs8State(x0, x1, x2, x3, x4, x5, x6, x7) = self;
        (Bs4State(x0, x1, x2, x3), Bs4State(x4, x5, x6, x7))
    }
}

impl<T: BitXor<Output = T> + Copy> Bs8State<T> {
    fn xor(self, rhs: Bs8State<T>) -> Bs8State<T> {
        let Bs8State(a0, a1, a2, a3, a4, a5, a6, a7) = self;
        let Bs8State(b0, b1, b2, b3, b4, b5, b6, b7) = rhs;
        Bs8State(
            a0 ^ b0,
            a1 ^ b1,
            a2 ^ b2,
            a3 ^ b3,
            a4 ^ b4,
            a5 ^ b5,
            a6 ^ b6,
            a7 ^ b7,
        )
    }

    // We need to be able to convert a Bs8State to and from a polynomial basis and a normal
    // basis. That transformation could be done via pseudocode that roughly looks like the
    // following:
    //
    // for x in 0..8 {
    //     for y in 0..8 {
    //         result.x ^= input.y & MATRIX[7 - y][x]
    //     }
    // }
    //
    // Where the MATRIX is one of the following depending on the conversion being done.
    // (The affine transformation step is included in all of these matrices):
    //
    // A2X = [
    //     [ 0,  0,  0, -1, -1,  0,  0, -1],
    //     [-1, -1,  0,  0, -1, -1, -1, -1],
    //     [ 0, -1,  0,  0, -1, -1, -1, -1],
    //     [ 0,  0,  0, -1,  0,  0, -1,  0],
    //     [-1,  0,  0, -1,  0,  0,  0,  0],
    //     [-1,  0,  0,  0,  0,  0,  0, -1],
    //     [-1,  0,  0, -1,  0, -1,  0, -1],
    //     [-1, -1, -1, -1, -1, -1, -1, -1]
    // ];
    //
    // X2A = [
    //     [ 0,  0, -1,  0,  0, -1, -1,  0],
    //     [ 0,  0,  0, -1, -1, -1, -1,  0],
    //     [ 0, -1, -1, -1,  0, -1, -1,  0],
    //     [ 0,  0, -1, -1,  0,  0,  0, -1],
    //     [ 0,  0,  0, -1,  0, -1, -1,  0],
    //     [-1,  0,  0, -1,  0, -1,  0,  0],
    //     [ 0, -1, -1, -1, -1,  0, -1, -1],
    //     [ 0,  0,  0,  0,  0, -1, -1,  0],
    // ];
    //
    // X2S = [
    //     [ 0,  0,  0, -1, -1,  0, -1,  0],
    //     [-1,  0, -1, -1,  0, -1,  0,  0],
    //     [ 0, -1, -1, -1, -1,  0,  0, -1],
    //     [-1, -1,  0, -1,  0,  0,  0,  0],
    //     [ 0,  0, -1, -1, -1,  0, -1, -1],
    //     [ 0,  0, -1,  0,  0,  0,  0,  0],
    //     [-1, -1,  0,  0,  0,  0,  0,  0],
    //     [ 0,  0, -1,  0,  0, -1,  0,  0],
    // ];
    //
    // S2X = [
    //     [ 0,  0, -1, -1,  0,  0,  0, -1],
    //     [-1,  0,  0, -1, -1, -1, -1,  0],
    //     [-1,  0, -1,  0,  0,  0,  0,  0],
    //     [-1, -1,  0, -1,  0, -1, -1, -1],
    //     [ 0, -1,  0,  0, -1,  0,  0,  0],
    //     [ 0,  0, -1,  0,  0,  0,  0,  0],
    //     [-1,  0,  0,  0, -1,  0, -1,  0],
    //     [-1, -1,  0,  0, -1,  0, -1,  0],
    // ];
    //
    // Looking at the pseudocode implementation, we see that there is no point
    // in processing any of the elements in those matrices that have zero values
    // since a logical AND with 0 will produce 0 which will have no effect when it
    // is XORed into the result.
    //
    // LLVM doesn't appear to be able to fully unroll the loops in the pseudocode
    // above and to eliminate processing of the 0 elements. So, each transformation is
    // implemented independently directly in fully unrolled form with the 0 elements
    // removed.
    //
    // As an optimization, elements that are XORed together multiple times are
    // XORed just once and then used multiple times. I wrote a simple program that
    // greedily looked for terms to combine to create the implementations below.
    // It is likely that this could be optimized more.

    fn change_basis_a2x(&self) -> Bs8State<T> {
        let t06 = self.6 ^ self.0;
        let t056 = self.5 ^ t06;
        let t0156 = t056 ^ self.1;
        let t13 = self.1 ^ self.3;

        let x0 = self.2 ^ t06 ^ t13;
        let x1 = t056;
        let x2 = self.0;
        let x3 = self.0 ^ self.4 ^ self.7 ^ t13;
        let x4 = self.7 ^ t056;
        let x5 = t0156;
        let x6 = self.4 ^ t056;
        let x7 = self.2 ^ self.7 ^ t0156;

        Bs8State(x0, x1, x2, x3, x4, x5, x6, x7)
    }

    fn change_basis_x2s(&self) -> Bs8State<T> {
        let t46 = self.4 ^ self.6;
        let t35 = self.3 ^ self.5;
        let t06 = self.0 ^ self.6;
        let t357 = t35 ^ self.7;

        let x0 = self.1 ^ t46;
        let x1 = self.1 ^ self.4 ^ self.5;
        let x2 = self.2 ^ t35 ^ t06;
        let x3 = t46 ^ t357;
        let x4 = t357;
        let x5 = t06;
        let x6 = self.3 ^ self.7;
        let x7 = t35;

        Bs8State(x0, x1, x2, x3, x4, x5, x6, x7)
    }

    fn change_basis_x2a(&self) -> Bs8State<T> {
        let t15 = self.1 ^ self.5;
        let t36 = self.3 ^ self.6;
        let t1356 = t15 ^ t36;
        let t07 = self.0 ^ self.7;

        let x0 = self.2;
        let x1 = t15;
        let x2 = self.4 ^ self.7 ^ t15;
        let x3 = self.2 ^ self.4 ^ t1356;
        let x4 = self.1 ^ self.6;
        let x5 = self.2 ^ self.5 ^ t36 ^ t07;
        let x6 = t1356 ^ t07;
        let x7 = self.1 ^ self.4;

        Bs8State(x0, x1, x2, x3, x4, x5, x6, x7)
    }

    fn change_basis_s2x(&self) -> Bs8State<T> {
        let t46 = self.4 ^ self.6;
        let t01 = self.0 ^ self.1;
        let t0146 = t01 ^ t46;

        let x0 = self.5 ^ t0146;
        let x1 = self.0 ^ self.3 ^ self.4;
        let x2 = self.2 ^ self.5 ^ self.7;
        let x3 = self.7 ^ t46;
        let x4 = self.3 ^ self.6 ^ t01;
        let x5 = t46;
        let x6 = t0146;
        let x7 = self.4 ^ self.7;

        Bs8State(x0, x1, x2, x3, x4, x5, x6, x7)
    }
}

impl<T: Not<Output = T> + Copy> Bs8State<T> {
    // The special value "x63" is used as part of the sub_bytes and inv_sub_bytes
    // steps. It is conceptually a Bs8State value where the 0th, 1st, 5th, and 6th
    // elements are all 1s and the other elements are all 0s. The only thing that
    // we do with the "x63" value is to XOR a Bs8State with it. We optimize that XOR
    // below into just inverting 4 of the elements and leaving the other 4 elements
    // untouched.
    fn xor_x63(self) -> Bs8State<T> {
        Bs8State(
            !self.0,
            !self.1,
            self.2,
            self.3,
            self.4,
            !self.5,
            !self.6,
            self.7,
        )
    }
}

#[derive(Clone, Copy)]
struct Bs4State<T>(T, T, T, T);

impl<T: Copy> Bs4State<T> {
    fn split(self) -> (Bs2State<T>, Bs2State<T>) {
        let Bs4State(x0, x1, x2, x3) = self;
        (Bs2State(x0, x1), Bs2State(x2, x3))
    }

    fn join(self, rhs: Bs4State<T>) -> Bs8State<T> {
        let Bs4State(a0, a1, a2, a3) = self;
        let Bs4State(b0, b1, b2, b3) = rhs;
        Bs8State(a0, a1, a2, a3, b0, b1, b2, b3)
    }
}

impl<T: BitXor<Output = T> + Copy> Bs4State<T> {
    fn xor(self, rhs: Bs4State<T>) -> Bs4State<T> {
        let Bs4State(a0, a1, a2, a3) = self;
        let Bs4State(b0, b1, b2, b3) = rhs;
        Bs4State(a0 ^ b0, a1 ^ b1, a2 ^ b2, a3 ^ b3)
    }
}

#[derive(Clone, Copy)]
struct Bs2State<T>(T, T);

impl<T> Bs2State<T> {
    fn split(self) -> (T, T) {
        let Bs2State(x0, x1) = self;
        (x0, x1)
    }

    fn join(self, rhs: Bs2State<T>) -> Bs4State<T> {
        let Bs2State(a0, a1) = self;
        let Bs2State(b0, b1) = rhs;
        Bs4State(a0, a1, b0, b1)
    }
}

impl<T: BitXor<Output = T> + Copy> Bs2State<T> {
    fn xor(self, rhs: Bs2State<T>) -> Bs2State<T> {
        let Bs2State(a0, a1) = self;
        let Bs2State(b0, b1) = rhs;
        Bs2State(a0 ^ b0, a1 ^ b1)
    }
}

// Bit Slice data in the form of 4 u32s in column-major order
#[inline(always)]
pub fn bit_slice_4x4_with_u16(a: u32, b: u32, c: u32, d: u32) -> Bs8State<u16> {
    fn pb(x: u32, bit: u32, shift: u32) -> u16 {
        (((x >> bit) & 1) as u16) << shift
    }

    fn construct(a: u32, b: u32, c: u32, d: u32, bit: u32) -> u16 {
        pb(a, bit, 0) | pb(b, bit, 1) | pb(c, bit, 2) | pb(d, bit, 3)
            | pb(a, bit + 8, 4) | pb(b, bit + 8, 5) | pb(c, bit + 8, 6)
            | pb(d, bit + 8, 7) | pb(a, bit + 16, 8)
            | pb(b, bit + 16, 9) | pb(c, bit + 16, 10)
            | pb(d, bit + 16, 11) | pb(a, bit + 24, 12)
            | pb(b, bit + 24, 13) | pb(c, bit + 24, 14)
            | pb(d, bit + 24, 15)
    }

    let x0 = construct(a, b, c, d, 0);
    let x1 = construct(a, b, c, d, 1);
    let x2 = construct(a, b, c, d, 2);
    let x3 = construct(a, b, c, d, 3);
    let x4 = construct(a, b, c, d, 4);
    let x5 = construct(a, b, c, d, 5);
    let x6 = construct(a, b, c, d, 6);
    let x7 = construct(a, b, c, d, 7);

    Bs8State(x0, x1, x2, x3, x4, x5, x6, x7)
}

// Bit slice a single u32 value - this is used to calculate the SubBytes step when creating the
// round keys.
pub fn bit_slice_4x1_with_u16(a: u32) -> Bs8State<u16> {
    bit_slice_4x4_with_u16(a, 0, 0, 0)
}

// Bit slice a 16 byte array in column major order
pub fn bit_slice_1x16_with_u16(data: &[u8]) -> Bs8State<u16> {
    let mut n = [0u32; 4];
    read_u32v_le(&mut n, data);

    let a = n[0];
    let b = n[1];
    let c = n[2];
    let d = n[3];

    bit_slice_4x4_with_u16(a, b, c, d)
}

// Un Bit Slice into a set of 4 u32s
pub fn un_bit_slice_4x4_with_u16(bs: &Bs8State<u16>) -> (u32, u32, u32, u32) {
    fn pb(x: u16, bit: u32, shift: u32) -> u32 {
        (((x >> bit) & 1) as u32) << shift
    }

    fn deconstruct(bs: &Bs8State<u16>, bit: u32) -> u32 {
        let Bs8State(x0, x1, x2, x3, x4, x5, x6, x7) = *bs;

        pb(x0, bit, 0) | pb(x1, bit, 1) | pb(x2, bit, 2) | pb(x3, bit, 3)
            | pb(x4, bit, 4) | pb(x5, bit, 5) | pb(x6, bit, 6)
            | pb(x7, bit, 7) | pb(x0, bit + 4, 8) | pb(x1, bit + 4, 9)
            | pb(x2, bit + 4, 10) | pb(x3, bit + 4, 11)
            | pb(x4, bit + 4, 12) | pb(x5, bit + 4, 13)
            | pb(x6, bit + 4, 14) | pb(x7, bit + 4, 15)
            | pb(x0, bit + 8, 16) | pb(x1, bit + 8, 17)
            | pb(x2, bit + 8, 18) | pb(x3, bit + 8, 19)
            | pb(x4, bit + 8, 20) | pb(x5, bit + 8, 21)
            | pb(x6, bit + 8, 22) | pb(x7, bit + 8, 23)
            | pb(x0, bit + 12, 24) | pb(x1, bit + 12, 25)
            | pb(x2, bit + 12, 26) | pb(x3, bit + 12, 27)
            | pb(x4, bit + 12, 28) | pb(x5, bit + 12, 29)
            | pb(x6, bit + 12, 30) | pb(x7, bit + 12, 31)
    }

    let a = deconstruct(bs, 0);
    let b = deconstruct(bs, 1);
    let c = deconstruct(bs, 2);
    let d = deconstruct(bs, 3);

    (a, b, c, d)
}

// Un Bit Slice into a single u32. This is used when creating the round keys.
pub fn un_bit_slice_4x1_with_u16(bs: &Bs8State<u16>) -> u32 {
    let (a, _, _, _) = un_bit_slice_4x4_with_u16(bs);
    a
}

// Un Bit Slice into a 16 byte array
pub fn un_bit_slice_1x16_with_u16(bs: &Bs8State<u16>, output: &mut [u8]) {
    let (a, b, c, d) = un_bit_slice_4x4_with_u16(bs);

    write_u32_le(&mut output[0..4], a);
    write_u32_le(&mut output[4..8], b);
    write_u32_le(&mut output[8..12], c);
    write_u32_le(&mut output[12..16], d);
}

// Bit Slice a 128 byte array of eight 16 byte blocks. Each block is in column major order.
pub fn bit_slice_1x128_with_u32x4(data: &[u8]) -> Bs8State<u32x4> {
    let bit0 = u32x4(0x01010101, 0x01010101, 0x01010101, 0x01010101);
    let bit1 = u32x4(0x02020202, 0x02020202, 0x02020202, 0x02020202);
    let bit2 = u32x4(0x04040404, 0x04040404, 0x04040404, 0x04040404);
    let bit3 = u32x4(0x08080808, 0x08080808, 0x08080808, 0x08080808);
    let bit4 = u32x4(0x10101010, 0x10101010, 0x10101010, 0x10101010);
    let bit5 = u32x4(0x20202020, 0x20202020, 0x20202020, 0x20202020);
    let bit6 = u32x4(0x40404040, 0x40404040, 0x40404040, 0x40404040);
    let bit7 = u32x4(0x80808080, 0x80808080, 0x80808080, 0x80808080);

    fn read_row_major(data: &[u8]) -> u32x4 {
        u32x4(
            (data[0] as u32) | ((data[4] as u32) << 8)
                | ((data[8] as u32) << 16)
                | ((data[12] as u32) << 24),
            (data[1] as u32) | ((data[5] as u32) << 8)
                | ((data[9] as u32) << 16)
                | ((data[13] as u32) << 24),
            (data[2] as u32) | ((data[6] as u32) << 8)
                | ((data[10] as u32) << 16)
                | ((data[14] as u32) << 24),
            (data[3] as u32) | ((data[7] as u32) << 8)
                | ((data[11] as u32) << 16)
                | ((data[15] as u32) << 24),
        )
    }

    let t0 = read_row_major(&data[0..16]);
    let t1 = read_row_major(&data[16..32]);
    let t2 = read_row_major(&data[32..48]);
    let t3 = read_row_major(&data[48..64]);
    let t4 = read_row_major(&data[64..80]);
    let t5 = read_row_major(&data[80..96]);
    let t6 = read_row_major(&data[96..112]);
    let t7 = read_row_major(&data[112..128]);

    let x0 = (t0 & bit0) | (t1.lsh(1) & bit1) | (t2.lsh(2) & bit2)
        | (t3.lsh(3) & bit3) | (t4.lsh(4) & bit4)
        | (t5.lsh(5) & bit5) | (t6.lsh(6) & bit6)
        | (t7.lsh(7) & bit7);
    let x1 = (t0.rsh(1) & bit0) | (t1 & bit1) | (t2.lsh(1) & bit2)
        | (t3.lsh(2) & bit3) | (t4.lsh(3) & bit4)
        | (t5.lsh(4) & bit5) | (t6.lsh(5) & bit6)
        | (t7.lsh(6) & bit7);
    let x2 = (t0.rsh(2) & bit0) | (t1.rsh(1) & bit1) | (t2 & bit2)
        | (t3.lsh(1) & bit3) | (t4.lsh(2) & bit4)
        | (t5.lsh(3) & bit5) | (t6.lsh(4) & bit6)
        | (t7.lsh(5) & bit7);
    let x3 = (t0.rsh(3) & bit0) | (t1.rsh(2) & bit1) | (t2.rsh(1) & bit2)
        | (t3 & bit3) | (t4.lsh(1) & bit4) | (t5.lsh(2) & bit5)
        | (t6.lsh(3) & bit6) | (t7.lsh(4) & bit7);
    let x4 = (t0.rsh(4) & bit0) | (t1.rsh(3) & bit1) | (t2.rsh(2) & bit2)
        | (t3.rsh(1) & bit3) | (t4 & bit4) | (t5.lsh(1) & bit5)
        | (t6.lsh(2) & bit6) | (t7.lsh(3) & bit7);
    let x5 = (t0.rsh(5) & bit0) | (t1.rsh(4) & bit1) | (t2.rsh(3) & bit2)
        | (t3.rsh(2) & bit3) | (t4.rsh(1) & bit4) | (t5 & bit5)
        | (t6.lsh(1) & bit6) | (t7.lsh(2) & bit7);
    let x6 = (t0.rsh(6) & bit0) | (t1.rsh(5) & bit1) | (t2.rsh(4) & bit2)
        | (t3.rsh(3) & bit3) | (t4.rsh(2) & bit4)
        | (t5.rsh(1) & bit5) | (t6 & bit6) | (t7.lsh(1) & bit7);
    let x7 = (t0.rsh(7) & bit0) | (t1.rsh(6) & bit1) | (t2.rsh(5) & bit2)
        | (t3.rsh(4) & bit3) | (t4.rsh(3) & bit4)
        | (t5.rsh(2) & bit5) | (t6.rsh(1) & bit6) | (t7 & bit7);

    Bs8State(x0, x1, x2, x3, x4, x5, x6, x7)
}

// Bit slice a set of 4 u32s by filling a full 128 byte data block with those repeated values. This
// is used as part of bit slicing the round keys.
pub fn bit_slice_fill_4x4_with_u32x4(
    a: u32, b: u32, c: u32, d: u32
) -> Bs8State<u32x4> {
    let mut tmp = [0u8; 128];
    for i in 0..8 {
        write_u32_le(&mut tmp[i * 16..i * 16 + 4], a);
        write_u32_le(&mut tmp[i * 16 + 4..i * 16 + 8], b);
        write_u32_le(&mut tmp[i * 16 + 8..i * 16 + 12], c);
        write_u32_le(&mut tmp[i * 16 + 12..i * 16 + 16], d);
    }
    bit_slice_1x128_with_u32x4(&tmp)
}

// Un bit slice into a 128 byte buffer.
pub fn un_bit_slice_1x128_with_u32x4(bs: Bs8State<u32x4>, output: &mut [u8]) {
    let Bs8State(t0, t1, t2, t3, t4, t5, t6, t7) = bs;

    let bit0 = u32x4(0x01010101, 0x01010101, 0x01010101, 0x01010101);
    let bit1 = u32x4(0x02020202, 0x02020202, 0x02020202, 0x02020202);
    let bit2 = u32x4(0x04040404, 0x04040404, 0x04040404, 0x04040404);
    let bit3 = u32x4(0x08080808, 0x08080808, 0x08080808, 0x08080808);
    let bit4 = u32x4(0x10101010, 0x10101010, 0x10101010, 0x10101010);
    let bit5 = u32x4(0x20202020, 0x20202020, 0x20202020, 0x20202020);
    let bit6 = u32x4(0x40404040, 0x40404040, 0x40404040, 0x40404040);
    let bit7 = u32x4(0x80808080, 0x80808080, 0x80808080, 0x80808080);

    // decode the individual blocks, in row-major order
    // TODO: this is identical to the same block in bit_slice_1x128_with_u32x4
    let x0 = (t0 & bit0) | (t1.lsh(1) & bit1) | (t2.lsh(2) & bit2)
        | (t3.lsh(3) & bit3) | (t4.lsh(4) & bit4)
        | (t5.lsh(5) & bit5) | (t6.lsh(6) & bit6)
        | (t7.lsh(7) & bit7);
    let x1 = (t0.rsh(1) & bit0) | (t1 & bit1) | (t2.lsh(1) & bit2)
        | (t3.lsh(2) & bit3) | (t4.lsh(3) & bit4)
        | (t5.lsh(4) & bit5) | (t6.lsh(5) & bit6)
        | (t7.lsh(6) & bit7);
    let x2 = (t0.rsh(2) & bit0) | (t1.rsh(1) & bit1) | (t2 & bit2)
        | (t3.lsh(1) & bit3) | (t4.lsh(2) & bit4)
        | (t5.lsh(3) & bit5) | (t6.lsh(4) & bit6)
        | (t7.lsh(5) & bit7);
    let x3 = (t0.rsh(3) & bit0) | (t1.rsh(2) & bit1) | (t2.rsh(1) & bit2)
        | (t3 & bit3) | (t4.lsh(1) & bit4) | (t5.lsh(2) & bit5)
        | (t6.lsh(3) & bit6) | (t7.lsh(4) & bit7);
    let x4 = (t0.rsh(4) & bit0) | (t1.rsh(3) & bit1) | (t2.rsh(2) & bit2)
        | (t3.rsh(1) & bit3) | (t4 & bit4) | (t5.lsh(1) & bit5)
        | (t6.lsh(2) & bit6) | (t7.lsh(3) & bit7);
    let x5 = (t0.rsh(5) & bit0) | (t1.rsh(4) & bit1) | (t2.rsh(3) & bit2)
        | (t3.rsh(2) & bit3) | (t4.rsh(1) & bit4) | (t5 & bit5)
        | (t6.lsh(1) & bit6) | (t7.lsh(2) & bit7);
    let x6 = (t0.rsh(6) & bit0) | (t1.rsh(5) & bit1) | (t2.rsh(4) & bit2)
        | (t3.rsh(3) & bit3) | (t4.rsh(2) & bit4)
        | (t5.rsh(1) & bit5) | (t6 & bit6) | (t7.lsh(1) & bit7);
    let x7 = (t0.rsh(7) & bit0) | (t1.rsh(6) & bit1) | (t2.rsh(5) & bit2)
        | (t3.rsh(4) & bit3) | (t4.rsh(3) & bit4)
        | (t5.rsh(2) & bit5) | (t6.rsh(1) & bit6) | (t7 & bit7);

    fn write_row_major(block: u32x4, output: &mut [u8]) {
        let u32x4(a0, a1, a2, a3) = block;
        output[0] = a0 as u8;
        output[1] = a1 as u8;
        output[2] = a2 as u8;
        output[3] = a3 as u8;
        output[4] = (a0 >> 8) as u8;
        output[5] = (a1 >> 8) as u8;
        output[6] = (a2 >> 8) as u8;
        output[7] = (a3 >> 8) as u8;
        output[8] = (a0 >> 16) as u8;
        output[9] = (a1 >> 16) as u8;
        output[10] = (a2 >> 16) as u8;
        output[11] = (a3 >> 16) as u8;
        output[12] = (a0 >> 24) as u8;
        output[13] = (a1 >> 24) as u8;
        output[14] = (a2 >> 24) as u8;
        output[15] = (a3 >> 24) as u8;
    }

    write_row_major(x0, &mut output[0..16]);
    write_row_major(x1, &mut output[16..32]);
    write_row_major(x2, &mut output[32..48]);
    write_row_major(x3, &mut output[48..64]);
    write_row_major(x4, &mut output[64..80]);
    write_row_major(x5, &mut output[80..96]);
    write_row_major(x6, &mut output[96..112]);
    write_row_major(x7, &mut output[112..128])
}

// The Gf2Ops, Gf4Ops, and Gf8Ops traits specify the functions needed to calculate the AES S-Box
// values. This particuar implementation of those S-Box values is taken from [7], so that is where
// to look for details on how all that all works. This includes the transformations matrices defined
// below for the change_basis operation on the u32 and u32x4 types.

// Operations in GF(2^2) using normal basis (Omega^2,Omega)
trait Gf2Ops {
    // multiply
    fn mul(self, y: Self) -> Self;

    // scale by N = Omega^2
    fn scl_n(self) -> Self;

    // scale by N^2 = Omega
    fn scl_n2(self) -> Self;

    // square
    fn sq(self) -> Self;

    // Same as sqaure
    fn inv(self) -> Self;
}

impl<T: BitXor<Output = T> + BitAnd<Output = T> + Copy> Gf2Ops for Bs2State<T> {
    fn mul(self, y: Bs2State<T>) -> Bs2State<T> {
        let (b, a) = self.split();
        let (d, c) = y.split();
        let e = (a ^ b) & (c ^ d);
        let p = (a & c) ^ e;
        let q = (b & d) ^ e;
        Bs2State(q, p)
    }

    fn scl_n(self) -> Bs2State<T> {
        let (b, a) = self.split();
        let q = a ^ b;
        Bs2State(q, b)
    }

    fn scl_n2(self) -> Bs2State<T> {
        let (b, a) = self.split();
        let p = a ^ b;
        let q = a;
        Bs2State(q, p)
    }

    fn sq(self) -> Bs2State<T> {
        let (b, a) = self.split();
        Bs2State(a, b)
    }

    fn inv(self) -> Bs2State<T> { self.sq() }
}

// Operations in GF(2^4) using normal basis (alpha^8,alpha^2)
trait Gf4Ops {
    // multiply
    fn mul(self, y: Self) -> Self;

    // square & scale by nu
    // nu = beta^8 = N^2*alpha^2, N = w^2
    fn sq_scl(self) -> Self;

    // inverse
    fn inv(self) -> Self;
}

impl<T: BitXor<Output = T> + BitAnd<Output = T> + Copy> Gf4Ops for Bs4State<T> {
    fn mul(self, y: Bs4State<T>) -> Bs4State<T> {
        let (b, a) = self.split();
        let (d, c) = y.split();
        let f = c.xor(d);
        let e = a.xor(b).mul(f).scl_n();
        let p = a.mul(c).xor(e);
        let q = b.mul(d).xor(e);
        q.join(p)
    }

    fn sq_scl(self) -> Bs4State<T> {
        let (b, a) = self.split();
        let p = a.xor(b).sq();
        let q = b.sq().scl_n2();
        q.join(p)
    }

    fn inv(self) -> Bs4State<T> {
        let (b, a) = self.split();
        let c = a.xor(b).sq().scl_n();
        let d = a.mul(b);
        let e = c.xor(d).inv();
        let p = e.mul(b);
        let q = e.mul(a);
        q.join(p)
    }
}

// Operations in GF(2^8) using normal basis (d^16,d)
trait Gf8Ops {
    // inverse
    fn inv(&self) -> Self;
}

impl<T: BitXor<Output = T> + BitAnd<Output = T> + Copy + Default> Gf8Ops
    for Bs8State<T>
{
    fn inv(&self) -> Bs8State<T> {
        let (b, a) = self.split();
        let c = a.xor(b).sq_scl();
        let d = a.mul(b);
        let e = c.xor(d).inv();
        let p = e.mul(b);
        let q = e.mul(a);
        q.join(p)
    }
}

impl<T: AesBitValueOps + Copy + 'static> AesOps for Bs8State<T> {
    fn sub_bytes(self) -> Bs8State<T> {
        let nb: Bs8State<T> = self.change_basis_a2x();
        let inv = nb.inv();
        let nb2: Bs8State<T> = inv.change_basis_x2s();
        nb2.xor_x63()
    }

    fn inv_sub_bytes(self) -> Bs8State<T> {
        let t = self.xor_x63();
        let nb: Bs8State<T> = t.change_basis_s2x();
        let inv = nb.inv();
        inv.change_basis_x2a()
    }

    fn shift_rows(self) -> Bs8State<T> {
        let Bs8State(x0, x1, x2, x3, x4, x5, x6, x7) = self;
        Bs8State(
            x0.shift_row(),
            x1.shift_row(),
            x2.shift_row(),
            x3.shift_row(),
            x4.shift_row(),
            x5.shift_row(),
            x6.shift_row(),
            x7.shift_row(),
        )
    }

    fn inv_shift_rows(self) -> Bs8State<T> {
        let Bs8State(x0, x1, x2, x3, x4, x5, x6, x7) = self;
        Bs8State(
            x0.inv_shift_row(),
            x1.inv_shift_row(),
            x2.inv_shift_row(),
            x3.inv_shift_row(),
            x4.inv_shift_row(),
            x5.inv_shift_row(),
            x6.inv_shift_row(),
            x7.inv_shift_row(),
        )
    }

    // Formula from [5]
    fn mix_columns(self) -> Bs8State<T> {
        let Bs8State(x0, x1, x2, x3, x4, x5, x6, x7) = self;

        let x0out = x7 ^ x7.ror1() ^ x0.ror1() ^ (x0 ^ x0.ror1()).ror2();
        let x1out = x0 ^ x0.ror1() ^ x7 ^ x7.ror1() ^ x1.ror1()
            ^ (x1 ^ x1.ror1()).ror2();
        let x2out = x1 ^ x1.ror1() ^ x2.ror1() ^ (x2 ^ x2.ror1()).ror2();
        let x3out = x2 ^ x2.ror1() ^ x7 ^ x7.ror1() ^ x3.ror1()
            ^ (x3 ^ x3.ror1()).ror2();
        let x4out = x3 ^ x3.ror1() ^ x7 ^ x7.ror1() ^ x4.ror1()
            ^ (x4 ^ x4.ror1()).ror2();
        let x5out = x4 ^ x4.ror1() ^ x5.ror1() ^ (x5 ^ x5.ror1()).ror2();
        let x6out = x5 ^ x5.ror1() ^ x6.ror1() ^ (x6 ^ x6.ror1()).ror2();
        let x7out = x6 ^ x6.ror1() ^ x7.ror1() ^ (x7 ^ x7.ror1()).ror2();

        Bs8State(x0out, x1out, x2out, x3out, x4out, x5out, x6out, x7out)
    }

    // Formula from [6]
    fn inv_mix_columns(self) -> Bs8State<T> {
        let Bs8State(x0, x1, x2, x3, x4, x5, x6, x7) = self;

        let x0out = x5 ^ x6 ^ x7 ^ (x5 ^ x7 ^ x0).ror1() ^ (x0 ^ x5 ^ x6).ror2()
            ^ (x5 ^ x0).ror3();
        let x1out = x5 ^ x0 ^ (x6 ^ x5 ^ x0 ^ x7 ^ x1).ror1()
            ^ (x1 ^ x7 ^ x5).ror2() ^ (x6 ^ x5 ^ x1).ror3();
        let x2out = x6 ^ x0 ^ x1 ^ (x7 ^ x6 ^ x1 ^ x2).ror1()
            ^ (x0 ^ x2 ^ x6).ror2() ^ (x7 ^ x6 ^ x2).ror3();
        let x3out = x0 ^ x5 ^ x1 ^ x6 ^ x2 ^ (x0 ^ x5 ^ x2 ^ x3).ror1()
            ^ (x0 ^ x1 ^ x3 ^ x5 ^ x6 ^ x7).ror2()
            ^ (x0 ^ x5 ^ x7 ^ x3).ror3();
        let x4out = x1 ^ x5 ^ x2 ^ x3 ^ (x1 ^ x6 ^ x5 ^ x3 ^ x7 ^ x4).ror1()
            ^ (x1 ^ x2 ^ x4 ^ x5 ^ x7).ror2()
            ^ (x1 ^ x5 ^ x6 ^ x4).ror3();
        let x5out = x2 ^ x6 ^ x3 ^ x4 ^ (x2 ^ x7 ^ x6 ^ x4 ^ x5).ror1()
            ^ (x2 ^ x3 ^ x5 ^ x6).ror2()
            ^ (x2 ^ x6 ^ x7 ^ x5).ror3();
        let x6out = x3 ^ x7 ^ x4 ^ x5 ^ (x3 ^ x7 ^ x5 ^ x6).ror1()
            ^ (x3 ^ x4 ^ x6 ^ x7).ror2()
            ^ (x3 ^ x7 ^ x6).ror3();
        let x7out = x4 ^ x5 ^ x6 ^ (x4 ^ x6 ^ x7).ror1() ^ (x4 ^ x5 ^ x7).ror2()
            ^ (x4 ^ x7).ror3();

        Bs8State(x0out, x1out, x2out, x3out, x4out, x5out, x6out, x7out)
    }

    fn add_round_key(self, rk: &Bs8State<T>) -> Bs8State<T> { self.xor(*rk) }
}

pub trait AesBitValueOps
    : BitXor<Output = Self>
    + BitAnd<Output = Self>
    + Not<Output = Self>
    + Default
    + Sized {
    fn shift_row(self) -> Self;
    fn inv_shift_row(self) -> Self;
    fn ror1(self) -> Self;
    fn ror2(self) -> Self;
    fn ror3(self) -> Self;
}

impl AesBitValueOps for u16 {
    fn shift_row(self) -> u16 {
        // first 4 bits represent first row - don't shift
        (self & 0x000f) |
        // next 4 bits represent 2nd row - left rotate 1 bit
        ((self & 0x00e0) >> 1) | ((self & 0x0010) << 3) |
        // next 4 bits represent 3rd row - left rotate 2 bits
        ((self & 0x0c00) >> 2) | ((self & 0x0300) << 2) |
        // next 4 bits represent 4th row - left rotate 3 bits
        ((self & 0x8000) >> 3) | ((self & 0x7000) << 1)
    }

    fn inv_shift_row(self) -> u16 {
        // first 4 bits represent first row - don't shift
        (self & 0x000f) |
        // next 4 bits represent 2nd row - right rotate 1 bit
        ((self & 0x0080) >> 3) | ((self & 0x0070) << 1) |
        // next 4 bits represent 3rd row - right rotate 2 bits
        ((self & 0x0c00) >> 2) | ((self & 0x0300) << 2) |
        // next 4 bits represent 4th row - right rotate 3 bits
        ((self & 0xe000) >> 1) | ((self & 0x1000) << 3)
    }

    fn ror1(self) -> u16 { self >> 4 | self << 12 }

    fn ror2(self) -> u16 { self >> 8 | self << 8 }

    fn ror3(self) -> u16 { self >> 12 | self << 4 }
}

impl u32x4 {
    fn lsh(self, s: u32) -> u32x4 {
        let u32x4(a0, a1, a2, a3) = self;
        u32x4(
            a0 << s,
            (a1 << s) | (a0 >> (32 - s)),
            (a2 << s) | (a1 >> (32 - s)),
            (a3 << s) | (a2 >> (32 - s)),
        )
    }

    fn rsh(self, s: u32) -> u32x4 {
        let u32x4(a0, a1, a2, a3) = self;
        u32x4(
            (a0 >> s) | (a1 << (32 - s)),
            (a1 >> s) | (a2 << (32 - s)),
            (a2 >> s) | (a3 << (32 - s)),
            a3 >> s,
        )
    }
}

impl Not for u32x4 {
    type Output = u32x4;

    fn not(self) -> u32x4 { self ^ U32X4_1 }
}

impl Default for u32x4 {
    fn default() -> u32x4 { u32x4(0, 0, 0, 0) }
}

impl AesBitValueOps for u32x4 {
    fn shift_row(self) -> u32x4 {
        let u32x4(a0, a1, a2, a3) = self;
        u32x4(
            a0,
            a1 >> 8 | a1 << 24,
            a2 >> 16 | a2 << 16,
            a3 >> 24 | a3 << 8,
        )
    }

    fn inv_shift_row(self) -> u32x4 {
        let u32x4(a0, a1, a2, a3) = self;
        u32x4(
            a0,
            a1 >> 24 | a1 << 8,
            a2 >> 16 | a2 << 16,
            a3 >> 8 | a3 << 24,
        )
    }

    fn ror1(self) -> u32x4 {
        let u32x4(a0, a1, a2, a3) = self;
        u32x4(a1, a2, a3, a0)
    }

    fn ror2(self) -> u32x4 {
        let u32x4(a0, a1, a2, a3) = self;
        u32x4(a2, a3, a0, a1)
    }

    fn ror3(self) -> u32x4 {
        let u32x4(a0, a1, a2, a3) = self;
        u32x4(a3, a0, a1, a2)
    }
}
