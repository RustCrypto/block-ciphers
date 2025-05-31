#![allow(unsafe_op_in_unsafe_fn)]

use crate::x86::{Block30, Simd128RoundKeys, Simd256RoundKeys, arch::*};
use cipher::inout::InOut;
use core::arch::asm;

#[inline]
pub(crate) unsafe fn broadcast_keys(keys: &Simd128RoundKeys<13>) -> Simd256RoundKeys<13> {
    [
        _mm256_broadcastsi128_si256(keys[0]),
        _mm256_broadcastsi128_si256(keys[1]),
        _mm256_broadcastsi128_si256(keys[2]),
        _mm256_broadcastsi128_si256(keys[3]),
        _mm256_broadcastsi128_si256(keys[4]),
        _mm256_broadcastsi128_si256(keys[5]),
        _mm256_broadcastsi128_si256(keys[6]),
        _mm256_broadcastsi128_si256(keys[7]),
        _mm256_broadcastsi128_si256(keys[8]),
        _mm256_broadcastsi128_si256(keys[9]),
        _mm256_broadcastsi128_si256(keys[10]),
        _mm256_broadcastsi128_si256(keys[11]),
        _mm256_broadcastsi128_si256(keys[12]),
    ]
}

#[target_feature(enable = "avx")]
#[inline]
pub(crate) unsafe fn encrypt30(
    simd_256_keys: &Simd256RoundKeys<13>,
    blocks: InOut<'_, '_, Block30>,
) {
    let (iptr, optr) = blocks.into_raw();
    let iptr = iptr.cast::<__m256i>();
    let optr = optr.cast::<__m256i>();

    // load plain-data
    let mut data0 = iptr.add(0).read_unaligned();
    let mut data1 = iptr.add(1).read_unaligned();
    let mut data2 = iptr.add(2).read_unaligned();
    let mut data3 = iptr.add(3).read_unaligned();
    let mut data4 = iptr.add(4).read_unaligned();
    let mut data5 = iptr.add(5).read_unaligned();
    let mut data6 = iptr.add(6).read_unaligned();
    let mut data7 = iptr.add(7).read_unaligned();
    let mut data8 = iptr.add(8).read_unaligned();
    let mut data9 = iptr.add(9).read_unaligned();
    let mut data10 = iptr.add(10).read_unaligned();
    let mut data11 = iptr.add(11).read_unaligned();
    let mut data12 = iptr.add(12).read_unaligned();
    let mut data13 = iptr.add(13).read_unaligned();
    let mut data14 = iptr.add(14).read_unaligned();

    asm! {
        // aes-128 round 0 encrypt
        "vmovdqu ymm0 , [{simd_256_keys} +  0 * 32]",
        "vpxord ymm1 , ymm1 , ymm0",
        "vpxord ymm2 , ymm2 , ymm0",
        "vpxord ymm3 , ymm3 , ymm0",
        "vpxord ymm4 , ymm4 , ymm0",
        "vpxord ymm5 , ymm5 , ymm0",
        "vpxord ymm6 , ymm6 , ymm0",
        "vpxord ymm7 , ymm7 , ymm0",
        "vpxord ymm8 , ymm8 , ymm0",
        "vpxord ymm9 , ymm9 , ymm0",
        "vpxord ymm10, ymm10, ymm0",
        "vpxord ymm11, ymm11, ymm0",
        "vpxord ymm12, ymm12, ymm0",
        "vpxord ymm13, ymm13, ymm0",
        "vpxord ymm14, ymm14, ymm0",
        "vpxord ymm15, ymm15, ymm0",
        // aes-128 round 1 encrypt
        "vmovdqu ymm0 , [{simd_256_keys} +  1 * 32]",
        "vaesenc ymm1 , ymm1 , ymm0",
        "vaesenc ymm2 , ymm2 , ymm0",
        "vaesenc ymm3 , ymm3 , ymm0",
        "vaesenc ymm4 , ymm4 , ymm0",
        "vaesenc ymm5 , ymm5 , ymm0",
        "vaesenc ymm6 , ymm6 , ymm0",
        "vaesenc ymm7 , ymm7 , ymm0",
        "vaesenc ymm8 , ymm8 , ymm0",
        "vaesenc ymm9 , ymm9 , ymm0",
        "vaesenc ymm10, ymm10, ymm0",
        "vaesenc ymm11, ymm11, ymm0",
        "vaesenc ymm12, ymm12, ymm0",
        "vaesenc ymm13, ymm13, ymm0",
        "vaesenc ymm14, ymm14, ymm0",
        "vaesenc ymm15, ymm15, ymm0",
        // aes-128 round 2 encrypt
        "vmovdqu ymm0 , [{simd_256_keys} +  2 * 32]",
        "vaesenc ymm1 , ymm1 , ymm0",
        "vaesenc ymm2 , ymm2 , ymm0",
        "vaesenc ymm3 , ymm3 , ymm0",
        "vaesenc ymm4 , ymm4 , ymm0",
        "vaesenc ymm5 , ymm5 , ymm0",
        "vaesenc ymm6 , ymm6 , ymm0",
        "vaesenc ymm7 , ymm7 , ymm0",
        "vaesenc ymm8 , ymm8 , ymm0",
        "vaesenc ymm9 , ymm9 , ymm0",
        "vaesenc ymm10, ymm10, ymm0",
        "vaesenc ymm11, ymm11, ymm0",
        "vaesenc ymm12, ymm12, ymm0",
        "vaesenc ymm13, ymm13, ymm0",
        "vaesenc ymm14, ymm14, ymm0",
        "vaesenc ymm15, ymm15, ymm0",
        // aes-128 round 3 encrypt
        "vmovdqu ymm0 , [{simd_256_keys} +  3 * 32]",
        "vaesenc ymm1 , ymm1 , ymm0",
        "vaesenc ymm2 , ymm2 , ymm0",
        "vaesenc ymm3 , ymm3 , ymm0",
        "vaesenc ymm4 , ymm4 , ymm0",
        "vaesenc ymm5 , ymm5 , ymm0",
        "vaesenc ymm6 , ymm6 , ymm0",
        "vaesenc ymm7 , ymm7 , ymm0",
        "vaesenc ymm8 , ymm8 , ymm0",
        "vaesenc ymm9 , ymm9 , ymm0",
        "vaesenc ymm10, ymm10, ymm0",
        "vaesenc ymm11, ymm11, ymm0",
        "vaesenc ymm12, ymm12, ymm0",
        "vaesenc ymm13, ymm13, ymm0",
        "vaesenc ymm14, ymm14, ymm0",
        "vaesenc ymm15, ymm15, ymm0",
        // aes-128 round 4 encrypt
        "vmovdqu ymm0 , [{simd_256_keys} +  4 * 32]",
        "vaesenc ymm1 , ymm1 , ymm0",
        "vaesenc ymm2 , ymm2 , ymm0",
        "vaesenc ymm3 , ymm3 , ymm0",
        "vaesenc ymm4 , ymm4 , ymm0",
        "vaesenc ymm5 , ymm5 , ymm0",
        "vaesenc ymm6 , ymm6 , ymm0",
        "vaesenc ymm7 , ymm7 , ymm0",
        "vaesenc ymm8 , ymm8 , ymm0",
        "vaesenc ymm9 , ymm9 , ymm0",
        "vaesenc ymm10, ymm10, ymm0",
        "vaesenc ymm11, ymm11, ymm0",
        "vaesenc ymm12, ymm12, ymm0",
        "vaesenc ymm13, ymm13, ymm0",
        "vaesenc ymm14, ymm14, ymm0",
        "vaesenc ymm15, ymm15, ymm0",
        // aes-128 round 5 encrypt
        "vmovdqu ymm0 , [{simd_256_keys} +  5 * 32]",
        "vaesenc ymm1 , ymm1 , ymm0",
        "vaesenc ymm2 , ymm2 , ymm0",
        "vaesenc ymm3 , ymm3 , ymm0",
        "vaesenc ymm4 , ymm4 , ymm0",
        "vaesenc ymm5 , ymm5 , ymm0",
        "vaesenc ymm6 , ymm6 , ymm0",
        "vaesenc ymm7 , ymm7 , ymm0",
        "vaesenc ymm8 , ymm8 , ymm0",
        "vaesenc ymm9 , ymm9 , ymm0",
        "vaesenc ymm10, ymm10, ymm0",
        "vaesenc ymm11, ymm11, ymm0",
        "vaesenc ymm12, ymm12, ymm0",
        "vaesenc ymm13, ymm13, ymm0",
        "vaesenc ymm14, ymm14, ymm0",
        "vaesenc ymm15, ymm15, ymm0",
        // aes-128 round 6 encrypt
        "vmovdqu ymm0 , [{simd_256_keys} +  6 * 32]",
        "vaesenc ymm1 , ymm1 , ymm0",
        "vaesenc ymm2 , ymm2 , ymm0",
        "vaesenc ymm3 , ymm3 , ymm0",
        "vaesenc ymm4 , ymm4 , ymm0",
        "vaesenc ymm5 , ymm5 , ymm0",
        "vaesenc ymm6 , ymm6 , ymm0",
        "vaesenc ymm7 , ymm7 , ymm0",
        "vaesenc ymm8 , ymm8 , ymm0",
        "vaesenc ymm9 , ymm9 , ymm0",
        "vaesenc ymm10, ymm10, ymm0",
        "vaesenc ymm11, ymm11, ymm0",
        "vaesenc ymm12, ymm12, ymm0",
        "vaesenc ymm13, ymm13, ymm0",
        "vaesenc ymm14, ymm14, ymm0",
        "vaesenc ymm15, ymm15, ymm0",
        // aes-128 round 7 encrypt
        "vmovdqu ymm0 , [{simd_256_keys} +  7 * 32]",
        "vaesenc ymm1 , ymm1 , ymm0",
        "vaesenc ymm2 , ymm2 , ymm0",
        "vaesenc ymm3 , ymm3 , ymm0",
        "vaesenc ymm4 , ymm4 , ymm0",
        "vaesenc ymm5 , ymm5 , ymm0",
        "vaesenc ymm6 , ymm6 , ymm0",
        "vaesenc ymm7 , ymm7 , ymm0",
        "vaesenc ymm8 , ymm8 , ymm0",
        "vaesenc ymm9 , ymm9 , ymm0",
        "vaesenc ymm10, ymm10, ymm0",
        "vaesenc ymm11, ymm11, ymm0",
        "vaesenc ymm12, ymm12, ymm0",
        "vaesenc ymm13, ymm13, ymm0",
        "vaesenc ymm14, ymm14, ymm0",
        "vaesenc ymm15, ymm15, ymm0",
        // aes-128 round 8 encrypt
        "vmovdqu ymm0 , [{simd_256_keys} +  8 * 32]",
        "vaesenc ymm1 , ymm1 , ymm0",
        "vaesenc ymm2 , ymm2 , ymm0",
        "vaesenc ymm3 , ymm3 , ymm0",
        "vaesenc ymm4 , ymm4 , ymm0",
        "vaesenc ymm5 , ymm5 , ymm0",
        "vaesenc ymm6 , ymm6 , ymm0",
        "vaesenc ymm7 , ymm7 , ymm0",
        "vaesenc ymm8 , ymm8 , ymm0",
        "vaesenc ymm9 , ymm9 , ymm0",
        "vaesenc ymm10, ymm10, ymm0",
        "vaesenc ymm11, ymm11, ymm0",
        "vaesenc ymm12, ymm12, ymm0",
        "vaesenc ymm13, ymm13, ymm0",
        "vaesenc ymm14, ymm14, ymm0",
        "vaesenc ymm15, ymm15, ymm0",
        // aes-128 round 9 encrypt
        "vmovdqu ymm0 , [{simd_256_keys} +  9 * 32]",
        "vaesenc ymm1 , ymm1 , ymm0",
        "vaesenc ymm2 , ymm2 , ymm0",
        "vaesenc ymm3 , ymm3 , ymm0",
        "vaesenc ymm4 , ymm4 , ymm0",
        "vaesenc ymm5 , ymm5 , ymm0",
        "vaesenc ymm6 , ymm6 , ymm0",
        "vaesenc ymm7 , ymm7 , ymm0",
        "vaesenc ymm8 , ymm8 , ymm0",
        "vaesenc ymm9 , ymm9 , ymm0",
        "vaesenc ymm10, ymm10, ymm0",
        "vaesenc ymm11, ymm11, ymm0",
        "vaesenc ymm12, ymm12, ymm0",
        "vaesenc ymm13, ymm13, ymm0",
        "vaesenc ymm14, ymm14, ymm0",
        "vaesenc ymm15, ymm15, ymm0",
        // aes-192 round 10 encrypt
        "vmovdqu ymm0 , [{simd_256_keys} + 10 * 32]",
        "vaesenc ymm1 , ymm1 , ymm0",
        "vaesenc ymm2 , ymm2 , ymm0",
        "vaesenc ymm3 , ymm3 , ymm0",
        "vaesenc ymm4 , ymm4 , ymm0",
        "vaesenc ymm5 , ymm5 , ymm0",
        "vaesenc ymm6 , ymm6 , ymm0",
        "vaesenc ymm7 , ymm7 , ymm0",
        "vaesenc ymm8 , ymm8 , ymm0",
        "vaesenc ymm9 , ymm9 , ymm0",
        "vaesenc ymm10, ymm10, ymm0",
        "vaesenc ymm11, ymm11, ymm0",
        "vaesenc ymm12, ymm12, ymm0",
        "vaesenc ymm13, ymm13, ymm0",
        "vaesenc ymm14, ymm14, ymm0",
        "vaesenc ymm15, ymm15, ymm0",
        // aes-192 round 11 encrypt
        "vmovdqu ymm0 , [{simd_256_keys} + 11 * 32]",
        "vaesenc ymm1 , ymm1 , ymm0",
        "vaesenc ymm2 , ymm2 , ymm0",
        "vaesenc ymm3 , ymm3 , ymm0",
        "vaesenc ymm4 , ymm4 , ymm0",
        "vaesenc ymm5 , ymm5 , ymm0",
        "vaesenc ymm6 , ymm6 , ymm0",
        "vaesenc ymm7 , ymm7 , ymm0",
        "vaesenc ymm8 , ymm8 , ymm0",
        "vaesenc ymm9 , ymm9 , ymm0",
        "vaesenc ymm10, ymm10, ymm0",
        "vaesenc ymm11, ymm11, ymm0",
        "vaesenc ymm12, ymm12, ymm0",
        "vaesenc ymm13, ymm13, ymm0",
        "vaesenc ymm14, ymm14, ymm0",
        "vaesenc ymm15, ymm15, ymm0",
        // aes-192 round 12 encrypt
        "vmovdqu ymm0, [{simd_256_keys} + 12 * 32]",
        "vaesenclast ymm1 , ymm1 , ymm0",
        "vaesenclast ymm2 , ymm2 , ymm0",
        "vaesenclast ymm3 , ymm3 , ymm0",
        "vaesenclast ymm4 , ymm4 , ymm0",
        "vaesenclast ymm5 , ymm5 , ymm0",
        "vaesenclast ymm6 , ymm6 , ymm0",
        "vaesenclast ymm7 , ymm7 , ymm0",
        "vaesenclast ymm8 , ymm8 , ymm0",
        "vaesenclast ymm9 , ymm9 , ymm0",
        "vaesenclast ymm10, ymm10, ymm0",
        "vaesenclast ymm11, ymm11, ymm0",
        "vaesenclast ymm12, ymm12, ymm0",
        "vaesenclast ymm13, ymm13, ymm0",
        "vaesenclast ymm14, ymm14, ymm0",
        "vaesenclast ymm15, ymm15, ymm0",

        simd_256_keys = in(reg) simd_256_keys.as_ptr(),

        out("ymm0") _,
        inout("ymm1")  data0,
        inout("ymm2")  data1,
        inout("ymm3")  data2,
        inout("ymm4")  data3,
        inout("ymm5")  data4,
        inout("ymm6")  data5,
        inout("ymm7")  data6,
        inout("ymm8")  data7,
        inout("ymm9")  data8,
        inout("ymm10") data9,
        inout("ymm11") data10,
        inout("ymm12") data11,
        inout("ymm13") data12,
        inout("ymm14") data13,
        inout("ymm15") data14,

        options(pure, readonly, nostack, preserves_flags),
    };

    // save cipher-data
    optr.add(0).write_unaligned(data0);
    optr.add(1).write_unaligned(data1);
    optr.add(2).write_unaligned(data2);
    optr.add(3).write_unaligned(data3);
    optr.add(4).write_unaligned(data4);
    optr.add(5).write_unaligned(data5);
    optr.add(6).write_unaligned(data6);
    optr.add(7).write_unaligned(data7);
    optr.add(8).write_unaligned(data8);
    optr.add(9).write_unaligned(data9);
    optr.add(10).write_unaligned(data10);
    optr.add(11).write_unaligned(data11);
    optr.add(12).write_unaligned(data12);
    optr.add(13).write_unaligned(data13);
    optr.add(14).write_unaligned(data14);
}

#[target_feature(enable = "avx")]
#[inline]
pub(crate) unsafe fn decrypt30(
    simd_256_keys: &Simd256RoundKeys<13>,
    blocks: InOut<'_, '_, Block30>,
) {
    let (iptr, optr) = blocks.into_raw();
    let iptr = iptr.cast::<__m256i>();
    let optr = optr.cast::<__m256i>();

    // load cipher-data
    let mut data0 = iptr.add(0).read_unaligned();
    let mut data1 = iptr.add(1).read_unaligned();
    let mut data2 = iptr.add(2).read_unaligned();
    let mut data3 = iptr.add(3).read_unaligned();
    let mut data4 = iptr.add(4).read_unaligned();
    let mut data5 = iptr.add(5).read_unaligned();
    let mut data6 = iptr.add(6).read_unaligned();
    let mut data7 = iptr.add(7).read_unaligned();
    let mut data8 = iptr.add(8).read_unaligned();
    let mut data9 = iptr.add(9).read_unaligned();
    let mut data10 = iptr.add(10).read_unaligned();
    let mut data11 = iptr.add(11).read_unaligned();
    let mut data12 = iptr.add(12).read_unaligned();
    let mut data13 = iptr.add(13).read_unaligned();
    let mut data14 = iptr.add(14).read_unaligned();

    asm! {
        // aes-192 round 12 decrypt
        "vmovdqu ymm0, [{simd_256_keys} +  0 * 32]",
        "vpxord ymm1 , ymm1 , ymm0",
        "vpxord ymm2 , ymm2 , ymm0",
        "vpxord ymm3 , ymm3 , ymm0",
        "vpxord ymm4 , ymm4 , ymm0",
        "vpxord ymm5 , ymm5 , ymm0",
        "vpxord ymm6 , ymm6 , ymm0",
        "vpxord ymm7 , ymm7 , ymm0",
        "vpxord ymm8 , ymm8 , ymm0",
        "vpxord ymm9 , ymm9 , ymm0",
        "vpxord ymm10, ymm10, ymm0",
        "vpxord ymm11, ymm11, ymm0",
        "vpxord ymm12, ymm12, ymm0",
        "vpxord ymm13, ymm13, ymm0",
        "vpxord ymm14, ymm14, ymm0",
        "vpxord ymm15, ymm15, ymm0",
        // aes-192 round 11 decrypt
        "vmovdqu ymm0 , [{simd_256_keys} +  1 * 32]",
        "vaesdec ymm1 , ymm1 , ymm0",
        "vaesdec ymm2 , ymm2 , ymm0",
        "vaesdec ymm3 , ymm3 , ymm0",
        "vaesdec ymm4 , ymm4 , ymm0",
        "vaesdec ymm5 , ymm5 , ymm0",
        "vaesdec ymm6 , ymm6 , ymm0",
        "vaesdec ymm7 , ymm7 , ymm0",
        "vaesdec ymm8 , ymm8 , ymm0",
        "vaesdec ymm9 , ymm9 , ymm0",
        "vaesdec ymm10, ymm10, ymm0",
        "vaesdec ymm11, ymm11, ymm0",
        "vaesdec ymm12, ymm12, ymm0",
        "vaesdec ymm13, ymm13, ymm0",
        "vaesdec ymm14, ymm14, ymm0",
        "vaesdec ymm15, ymm15, ymm0",
        // aes-192 round 10 decrypt
        "vmovdqu ymm0 , [{simd_256_keys} +  2 * 32]",
        "vaesdec ymm1 , ymm1 , ymm0",
        "vaesdec ymm2 , ymm2 , ymm0",
        "vaesdec ymm3 , ymm3 , ymm0",
        "vaesdec ymm4 , ymm4 , ymm0",
        "vaesdec ymm5 , ymm5 , ymm0",
        "vaesdec ymm6 , ymm6 , ymm0",
        "vaesdec ymm7 , ymm7 , ymm0",
        "vaesdec ymm8 , ymm8 , ymm0",
        "vaesdec ymm9 , ymm9 , ymm0",
        "vaesdec ymm10, ymm10, ymm0",
        "vaesdec ymm11, ymm11, ymm0",
        "vaesdec ymm12, ymm12, ymm0",
        "vaesdec ymm13, ymm13, ymm0",
        "vaesdec ymm14, ymm14, ymm0",
        "vaesdec ymm15, ymm15, ymm0",
        // aes-192 round 9 decrypt
        "vmovdqu ymm0 , [{simd_256_keys} +  3 * 32]",
        "vaesdec ymm1 , ymm1 , ymm0",
        "vaesdec ymm2 , ymm2 , ymm0",
        "vaesdec ymm3 , ymm3 , ymm0",
        "vaesdec ymm4 , ymm4 , ymm0",
        "vaesdec ymm5 , ymm5 , ymm0",
        "vaesdec ymm6 , ymm6 , ymm0",
        "vaesdec ymm7 , ymm7 , ymm0",
        "vaesdec ymm8 , ymm8 , ymm0",
        "vaesdec ymm9 , ymm9 , ymm0",
        "vaesdec ymm10, ymm10, ymm0",
        "vaesdec ymm11, ymm11, ymm0",
        "vaesdec ymm12, ymm12, ymm0",
        "vaesdec ymm13, ymm13, ymm0",
        "vaesdec ymm14, ymm14, ymm0",
        "vaesdec ymm15, ymm15, ymm0",
        // aes-192 round 8 decrypt
        "vmovdqu ymm0 , [{simd_256_keys} +  4 * 32]",
        "vaesdec ymm1 , ymm1 , ymm0",
        "vaesdec ymm2 , ymm2 , ymm0",
        "vaesdec ymm3 , ymm3 , ymm0",
        "vaesdec ymm4 , ymm4 , ymm0",
        "vaesdec ymm5 , ymm5 , ymm0",
        "vaesdec ymm6 , ymm6 , ymm0",
        "vaesdec ymm7 , ymm7 , ymm0",
        "vaesdec ymm8 , ymm8 , ymm0",
        "vaesdec ymm9 , ymm9 , ymm0",
        "vaesdec ymm10, ymm10, ymm0",
        "vaesdec ymm11, ymm11, ymm0",
        "vaesdec ymm12, ymm12, ymm0",
        "vaesdec ymm13, ymm13, ymm0",
        "vaesdec ymm14, ymm14, ymm0",
        "vaesdec ymm15, ymm15, ymm0",
        // aes-192 round 7 decrypt
        "vmovdqu ymm0 , [{simd_256_keys} +  5 * 32]",
        "vaesdec ymm1 , ymm1 , ymm0",
        "vaesdec ymm2 , ymm2 , ymm0",
        "vaesdec ymm3 , ymm3 , ymm0",
        "vaesdec ymm4 , ymm4 , ymm0",
        "vaesdec ymm5 , ymm5 , ymm0",
        "vaesdec ymm6 , ymm6 , ymm0",
        "vaesdec ymm7 , ymm7 , ymm0",
        "vaesdec ymm8 , ymm8 , ymm0",
        "vaesdec ymm9 , ymm9 , ymm0",
        "vaesdec ymm10, ymm10, ymm0",
        "vaesdec ymm11, ymm11, ymm0",
        "vaesdec ymm12, ymm12, ymm0",
        "vaesdec ymm13, ymm13, ymm0",
        "vaesdec ymm14, ymm14, ymm0",
        "vaesdec ymm15, ymm15, ymm0",
        // aes-192 round 6 decrypt
        "vmovdqu ymm0 , [{simd_256_keys} +  6 * 32]",
        "vaesdec ymm1 , ymm1 , ymm0",
        "vaesdec ymm2 , ymm2 , ymm0",
        "vaesdec ymm3 , ymm3 , ymm0",
        "vaesdec ymm4 , ymm4 , ymm0",
        "vaesdec ymm5 , ymm5 , ymm0",
        "vaesdec ymm6 , ymm6 , ymm0",
        "vaesdec ymm7 , ymm7 , ymm0",
        "vaesdec ymm8 , ymm8 , ymm0",
        "vaesdec ymm9 , ymm9 , ymm0",
        "vaesdec ymm10, ymm10, ymm0",
        "vaesdec ymm11, ymm11, ymm0",
        "vaesdec ymm12, ymm12, ymm0",
        "vaesdec ymm13, ymm13, ymm0",
        "vaesdec ymm14, ymm14, ymm0",
        "vaesdec ymm15, ymm15, ymm0",
        // aes-192 round 5 decrypt
        "vmovdqu ymm0 , [{simd_256_keys} +  7 * 32]",
        "vaesdec ymm1 , ymm1 , ymm0",
        "vaesdec ymm2 , ymm2 , ymm0",
        "vaesdec ymm3 , ymm3 , ymm0",
        "vaesdec ymm4 , ymm4 , ymm0",
        "vaesdec ymm5 , ymm5 , ymm0",
        "vaesdec ymm6 , ymm6 , ymm0",
        "vaesdec ymm7 , ymm7 , ymm0",
        "vaesdec ymm8 , ymm8 , ymm0",
        "vaesdec ymm9 , ymm9 , ymm0",
        "vaesdec ymm10, ymm10, ymm0",
        "vaesdec ymm11, ymm11, ymm0",
        "vaesdec ymm12, ymm12, ymm0",
        "vaesdec ymm13, ymm13, ymm0",
        "vaesdec ymm14, ymm14, ymm0",
        "vaesdec ymm15, ymm15, ymm0",
        // aes-192 round 4 decrypt
        "vmovdqu ymm0 , [{simd_256_keys} +  8 * 32]",
        "vaesdec ymm1 , ymm1 , ymm0",
        "vaesdec ymm2 , ymm2 , ymm0",
        "vaesdec ymm3 , ymm3 , ymm0",
        "vaesdec ymm4 , ymm4 , ymm0",
        "vaesdec ymm5 , ymm5 , ymm0",
        "vaesdec ymm6 , ymm6 , ymm0",
        "vaesdec ymm7 , ymm7 , ymm0",
        "vaesdec ymm8 , ymm8 , ymm0",
        "vaesdec ymm9 , ymm9 , ymm0",
        "vaesdec ymm10, ymm10, ymm0",
        "vaesdec ymm11, ymm11, ymm0",
        "vaesdec ymm12, ymm12, ymm0",
        "vaesdec ymm13, ymm13, ymm0",
        "vaesdec ymm14, ymm14, ymm0",
        "vaesdec ymm15, ymm15, ymm0",
        // aes-192 round 3 decrypt
        "vmovdqu ymm0 , [{simd_256_keys} +  9 * 32]",
        "vaesdec ymm1 , ymm1 , ymm0",
        "vaesdec ymm2 , ymm2 , ymm0",
        "vaesdec ymm3 , ymm3 , ymm0",
        "vaesdec ymm4 , ymm4 , ymm0",
        "vaesdec ymm5 , ymm5 , ymm0",
        "vaesdec ymm6 , ymm6 , ymm0",
        "vaesdec ymm7 , ymm7 , ymm0",
        "vaesdec ymm8 , ymm8 , ymm0",
        "vaesdec ymm9 , ymm9 , ymm0",
        "vaesdec ymm10, ymm10, ymm0",
        "vaesdec ymm11, ymm11, ymm0",
        "vaesdec ymm12, ymm12, ymm0",
        "vaesdec ymm13, ymm13, ymm0",
        "vaesdec ymm14, ymm14, ymm0",
        "vaesdec ymm15, ymm15, ymm0",
        // aes-192 round 2 decrypt
        "vmovdqu ymm0 , [{simd_256_keys} + 10 * 32]",
        "vaesdec ymm1 , ymm1 , ymm0",
        "vaesdec ymm2 , ymm2 , ymm0",
        "vaesdec ymm3 , ymm3 , ymm0",
        "vaesdec ymm4 , ymm4 , ymm0",
        "vaesdec ymm5 , ymm5 , ymm0",
        "vaesdec ymm6 , ymm6 , ymm0",
        "vaesdec ymm7 , ymm7 , ymm0",
        "vaesdec ymm8 , ymm8 , ymm0",
        "vaesdec ymm9 , ymm9 , ymm0",
        "vaesdec ymm10, ymm10, ymm0",
        "vaesdec ymm11, ymm11, ymm0",
        "vaesdec ymm12, ymm12, ymm0",
        "vaesdec ymm13, ymm13, ymm0",
        "vaesdec ymm14, ymm14, ymm0",
        "vaesdec ymm15, ymm15, ymm0",
        // aes-192 round 1 decrypt
        "vmovdqu ymm0 , [{simd_256_keys} + 11 * 32]",
        "vaesdec ymm1 , ymm1 , ymm0",
        "vaesdec ymm2 , ymm2 , ymm0",
        "vaesdec ymm3 , ymm3 , ymm0",
        "vaesdec ymm4 , ymm4 , ymm0",
        "vaesdec ymm5 , ymm5 , ymm0",
        "vaesdec ymm6 , ymm6 , ymm0",
        "vaesdec ymm7 , ymm7 , ymm0",
        "vaesdec ymm8 , ymm8 , ymm0",
        "vaesdec ymm9 , ymm9 , ymm0",
        "vaesdec ymm10, ymm10, ymm0",
        "vaesdec ymm11, ymm11, ymm0",
        "vaesdec ymm12, ymm12, ymm0",
        "vaesdec ymm13, ymm13, ymm0",
        "vaesdec ymm14, ymm14, ymm0",
        "vaesdec ymm15, ymm15, ymm0",
        // aes-192 round 0 decrypt
        "vmovdqu ymm0 , [{simd_256_keys} + 12 * 32]",
        "vaesdeclast ymm1 , ymm1 , ymm0",
        "vaesdeclast ymm2 , ymm2 , ymm0",
        "vaesdeclast ymm3 , ymm3 , ymm0",
        "vaesdeclast ymm4 , ymm4 , ymm0",
        "vaesdeclast ymm5 , ymm5 , ymm0",
        "vaesdeclast ymm6 , ymm6 , ymm0",
        "vaesdeclast ymm7 , ymm7 , ymm0",
        "vaesdeclast ymm8 , ymm8 , ymm0",
        "vaesdeclast ymm9 , ymm9 , ymm0",
        "vaesdeclast ymm10, ymm10, ymm0",
        "vaesdeclast ymm11, ymm11, ymm0",
        "vaesdeclast ymm12, ymm12, ymm0",
        "vaesdeclast ymm13, ymm13, ymm0",
        "vaesdeclast ymm14, ymm14, ymm0",
        "vaesdeclast ymm15, ymm15, ymm0",

        simd_256_keys = in(reg) simd_256_keys.as_ptr(),

        out("ymm0") _,
        inout("ymm1")  data0,
        inout("ymm2")  data1,
        inout("ymm3")  data2,
        inout("ymm4")  data3,
        inout("ymm5")  data4,
        inout("ymm6")  data5,
        inout("ymm7")  data6,
        inout("ymm8")  data7,
        inout("ymm9")  data8,
        inout("ymm10") data9,
        inout("ymm11") data10,
        inout("ymm12") data11,
        inout("ymm13") data12,
        inout("ymm14") data13,
        inout("ymm15") data14,

        options(pure, readonly, nostack, preserves_flags),
    };

    // save plain-data
    optr.add(0).write_unaligned(data0);
    optr.add(1).write_unaligned(data1);
    optr.add(2).write_unaligned(data2);
    optr.add(3).write_unaligned(data3);
    optr.add(4).write_unaligned(data4);
    optr.add(5).write_unaligned(data5);
    optr.add(6).write_unaligned(data6);
    optr.add(7).write_unaligned(data7);
    optr.add(8).write_unaligned(data8);
    optr.add(9).write_unaligned(data9);
    optr.add(10).write_unaligned(data10);
    optr.add(11).write_unaligned(data11);
    optr.add(12).write_unaligned(data12);
    optr.add(13).write_unaligned(data13);
    optr.add(14).write_unaligned(data14);
}
