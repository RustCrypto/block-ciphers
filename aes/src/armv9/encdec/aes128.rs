use crate::Block;
use crate::armv9::RoundKeys;
use cipher::{Array, array::ArraySize, inout::InOut};
use core::arch::global_asm;

#[rustfmt::skip]
global_asm! {
    // INPUTS:
    //      {x0} dst: *mut u8
    //      {x1} src: *const u8
    //      {x2} len: usize
    //      {x3} key: *const u8
    // SAFETY:
    //      - x0, x1 must be valid pointers to memory regions of at least len bytes
    //      - x3     must be valid pointers to memory regions of at least 176 bytes
    //      - on exit: x1 and x3 remain unchanged
    //      - on exit: x0 is overwritten with cipher-data
    ".balign 8",
    ".arch armv8-a+sve-aes+sve2",
    ".global aes_armv9_encdec_aes128_encrypt",
    ".type aes_armv9_encdec_aes128_encrypt, %function",
    "aes_armv9_encdec_aes128_encrypt:",
        "mov x8, #0",                           // loop counter {x8} := 0

        "whilelt p0.b, x8, x2",                 // avl := len {x2} - loop counter {x8}
        "b.none 2f",                            // exit if avl == 0

        "ld1rqb {{ z0.b}}, p0/z, [x3, #0 ]",    // broadcast load round 00 key
        "ld1rqb {{ z1.b}}, p0/z, [x3, #16]",    // broadcast load round 01 key
        "ld1rqb {{ z2.b}}, p0/z, [x3, #32]",    // broadcast load round 02 key
        "ld1rqb {{ z3.b}}, p0/z, [x3, #48]",    // broadcast load round 03 key
        "add x3, x3, #64",                      // key pointer += 64 bytes <4 keys>

        "ld1rqb {{ z4.b}}, p0/z, [x3, #0 ]",    // broadcast load round 04 key
        "ld1rqb {{ z5.b}}, p0/z, [x3, #16]",    // broadcast load round 05 key
        "ld1rqb {{ z6.b}}, p0/z, [x3, #32]",    // broadcast load round 06 key
        "ld1rqb {{ z7.b}}, p0/z, [x3, #48]",    // broadcast load round 07 key
        "add x3, x3, #64",                      // key pointer += 64 bytes <4 keys>

        "ld1rqb {{ z8.b}}, p0/z, [x3, #0 ]",    // broadcast load round 08 key
        "ld1rqb {{ z9.b}}, p0/z, [x3, #16]",    // broadcast load round 09 key
        "ld1rqb {{z10.b}}, p0/z, [x3, #32]",    // broadcast load round 10 key
    "1:",
        "ld1b  z31.b, p0/z, [x1]",              // data := plain[..avl <bytes>]

        "aese  z31.b, z31.b,  z0.b",            // perform AES-128 round 00 encryption
        "aesmc z31.b, z31.b",
        "aese  z31.b, z31.b,  z1.b",            // perform AES-128 round 01 encryption
        "aesmc z31.b, z31.b",
        "aese  z31.b, z31.b,  z2.b",            // perform AES-128 round 02 encryption
        "aesmc z31.b, z31.b",
        "aese  z31.b, z31.b,  z3.b",            // perform AES-128 round 03 encryption
        "aesmc z31.b, z31.b",
        "aese  z31.b, z31.b,  z4.b",            // perform AES-128 round 04 encryption
        "aesmc z31.b, z31.b",
        "aese  z31.b, z31.b,  z5.b",            // perform AES-128 round 05 encryption
        "aesmc z31.b, z31.b",
        "aese  z31.b, z31.b,  z6.b",            // perform AES-128 round 06 encryption
        "aesmc z31.b, z31.b",
        "aese  z31.b, z31.b,  z7.b",            // perform AES-128 round 07 encryption
        "aesmc z31.b, z31.b",
        "aese  z31.b, z31.b,  z8.b",            // perform AES-128 round 08 encryption
        "aesmc z31.b, z31.b",
        "aese  z31.b, z31.b,  z9.b",            // perform AES-128 round 09 encryption
        "eor   z31.b, z31.b, z10.b",            // perform AES-128 round 10 encryption

        "st1b  z31.b, p0, [x0]",                // cipher[..avl <bytes>] := data

        "incb x0",                              //  plain pointer += avl
        "incb x1",                              // cipher pointer += avl
        "incb x8",                              //   loop counter += avl

        "whilelt p0.b, x8, x2",                 // avl := len {x2} - loop counter {x8}
        "b.first 1b",                           // loop if (0 < avl)
    "2:",
        "ret",
}
unsafe extern "C" {
    pub fn aes_armv9_encdec_aes128_encrypt(
        dst: *mut u8,
        src: *const u8,
        len: usize,
        key: *const u8,
    );
}

#[rustfmt::skip]
global_asm! {
    // INPUTS:
    //      {x0} dst: *mut u8
    //      {x1} src: *const u8
    //      {x2} len: usize
    //      {x3} key: *const u8
    // SAFETY:
    //      - x0, x1 must be valid pointers to memory regions of at least len bytes
    //      - x3     must be valid pointers to memory regions of at least 176 bytes
    //      - on exit: x1, x3 are unchanged
    //      - on exit: x0 is overwritten with plain-data
    ".balign 8",
    ".arch armv8-a+sve-aes+sve2",
    ".global aes_armv9_encdec_aes128_decrypt",
    ".type aes_armv9_encdec_aes128_decrypt, %function",
    "aes_armv9_encdec_aes128_decrypt:",
        "mov x8, #0",                           // loop counter {x8} := 0

        "whilelt p0.b, x8, x2",                 // avl := len {x2} - loop counter {x8}
        "b.none 2f",                            // exit if avl == 0

        "ld1rqb {{ z0.b}}, p0/z, [x3, #0 ]",    // broadcast load round 00 key
        "ld1rqb {{ z1.b}}, p0/z, [x3, #16]",    // broadcast load round 01 key
        "ld1rqb {{ z2.b}}, p0/z, [x3, #32]",    // broadcast load round 02 key
        "ld1rqb {{ z3.b}}, p0/z, [x3, #48]",    // broadcast load round 03 key
        "add x3, x3, #64",                      // key pointer += 64 <4 keys>

        "ld1rqb {{ z4.b}}, p0/z, [x3, #0 ]",    // broadcast load round 04 key
        "ld1rqb {{ z5.b}}, p0/z, [x3, #16]",    // broadcast load round 05 key
        "ld1rqb {{ z6.b}}, p0/z, [x3, #32]",    // broadcast load round 06 key
        "ld1rqb {{ z7.b}}, p0/z, [x3, #48]",    // broadcast load round 07 key
        "add x3, x3, #64",                      // key pointer += 64 <4 keys>

        "ld1rqb {{ z8.b}}, p0/z, [x3, #0 ]",    // broadcast load round 08 key
        "ld1rqb {{ z9.b}}, p0/z, [x3, #16]",    // broadcast load round 09 key
        "ld1rqb {{z10.b}}, p0/z, [x3, #32]",    // broadcast load round 10 key
    "1:",
        "ld1b   z31.b, p0/z, [x1]",             // data := cipher[..avl <bytes>]

        "aesd   z31.b, z31.b,  z0.b",           // perform AES-128 round 00 decryption
        "aesimc z31.b, z31.b",
        "aesd   z31.b, z31.b,  z1.b",           // perform AES-128 round 01 decryption
        "aesimc z31.b, z31.b",
        "aesd   z31.b, z31.b,  z2.b",           // perform AES-128 round 02 decryption
        "aesimc z31.b, z31.b",
        "aesd   z31.b, z31.b,  z3.b",           // perform AES-128 round 03 decryption
        "aesimc z31.b, z31.b",
        "aesd   z31.b, z31.b,  z4.b",           // perform AES-128 round 04 decryption
        "aesimc z31.b, z31.b",
        "aesd   z31.b, z31.b,  z5.b",           // perform AES-128 round 05 decryption
        "aesimc z31.b, z31.b",
        "aesd   z31.b, z31.b,  z6.b",           // perform AES-128 round 06 decryption
        "aesimc z31.b, z31.b",
        "aesd   z31.b, z31.b,  z7.b",           // perform AES-128 round 07 decryption
        "aesimc z31.b, z31.b",
        "aesd   z31.b, z31.b,  z8.b",           // perform AES-128 round 08 decryption
        "aesimc z31.b, z31.b",
        "aesd   z31.b, z31.b,  z9.b",           // perform AES-128 round 09 decryption
        "eor    z31.b, z31.b, z10.b",           // perform AES-128 round 10 decryption

        "st1b   z31.b, p0, [x0]",               // plain[..avl <bytes>] := data

        "incb x0",                              //  plain pointer += avl
        "incb x1",                              // cipher pointer += avl
        "incb x8",                              //   loop counter += avl

        "whilelt p0.b, x8, x2",                 // avl := len {x2} - loop counter {x8}
        "b.first 1b",                           // loop if (0 < avl)
    "2:",
        "ret",
}
unsafe extern "C" {
    pub fn aes_armv9_encdec_aes128_decrypt(
        dst: *mut u8,
        src: *const u8,
        len: usize,
        key: *const u8,
    );
}

#[inline(always)]
pub fn encrypt_vla(keys: &RoundKeys<11>, mut data: InOut<'_, '_, Block>, blocks: usize) {
    let dst = data.get_out().as_mut_ptr();
    let src = data.get_in().as_ptr();
    let len = blocks * 16;
    let key = keys.as_ptr().cast::<u8>();
    unsafe { aes_armv9_encdec_aes128_encrypt(dst, src, len, key) };
}

#[inline(always)]
pub(crate) fn encrypt_all<ParBlocks>(
    keys: &RoundKeys<11>,
    mut data: InOut<'_, '_, Array<Block, ParBlocks>>,
) where
    ParBlocks: ArraySize,
{
    let data = unsafe {
        InOut::from_raw(
            data.get_in().as_ptr().cast::<Block>(),
            data.get_out().as_mut_ptr().cast::<Block>(),
        )
    };
    encrypt_vla(keys, data, ParBlocks::USIZE)
}

#[inline(always)]
pub fn decrypt_vla(keys: &RoundKeys<11>, mut data: InOut<'_, '_, Block>, blocks: usize) {
    let dst = data.get_out().as_mut_ptr();
    let src = data.get_in().as_ptr();
    let len = blocks * 16;
    let key = keys.as_ptr().cast::<u8>();
    unsafe { aes_armv9_encdec_aes128_decrypt(dst, src, len, key) };
}

#[inline(always)]
pub(crate) fn decrypt_all<ParBlocks>(
    keys: &RoundKeys<11>,
    mut data: InOut<'_, '_, Array<Block, ParBlocks>>,
) where
    ParBlocks: ArraySize,
{
    let data = unsafe {
        InOut::from_raw(
            data.get_in().as_ptr().cast::<Block>(),
            data.get_out().as_mut_ptr().cast::<Block>(),
        )
    };
    decrypt_vla(keys, data, ParBlocks::USIZE)
}
