use super::RoundKeys;
use crate::{Block, Block8};
use cipher::inout::InOut;
use core::arch::global_asm;

// TODO(silvanshade): switch to intrinsics when available
#[rustfmt::skip]
global_asm! {
    ".balign 8",                                                    // align section to 8 bytes
    ".global aes_armv9_encdec_aes128_encrypt",                      // declare symbol
    ".type aes_armv9_encdec_aes128_encrypt, %function",             // declare symbol as function type
    "aes_armv9_encdec_aes128_encrypt:",                             // start function
        "mov x8, #0",                                               // set loop counter {x8} to 0

        "whilelt p0.b, x8, x2",                                     // set avl to len {x2} - loop counter {x8}, represented as a predicate
        "b.none 2f",                                                // exit if avl == 0

        "ld1rqb {{ z0.b}}, p0/z, [x3, #0 ]",                        // broadcast load round 00 key
        "ld1rqb {{ z1.b}}, p0/z, [x3, #16]",                        // broadcast load round 01 key
        "ld1rqb {{ z2.b}}, p0/z, [x3, #32]",                        // broadcast load round 02 key
        "ld1rqb {{ z3.b}}, p0/z, [x3, #48]", "add x3, x3, #64",     // broadcast load round 03 key; increment key pointer by 4 indices
        "ld1rqb {{ z4.b}}, p0/z, [x3, #0 ]",                        // broadcast load round 04 key
        "ld1rqb {{ z5.b}}, p0/z, [x3, #16]",                        // broadcast load round 05 key
        "ld1rqb {{ z6.b}}, p0/z, [x3, #32]",                        // broadcast load round 06 key
        "ld1rqb {{ z7.b}}, p0/z, [x3, #48]", "add x3, x3, #64",     // broadcast load round 07 key; increment key pointer by 4 indices
        "ld1rqb {{ z8.b}}, p0/z, [x3, #0 ]",                        // broadcast load round 08 key
        "ld1rqb {{ z9.b}}, p0/z, [x3, #16]",                        // broadcast load round 09 key
        "ld1rqb {{z10.b}}, p0/z, [x3, #32]",                        // broadcast load round 10 key
    "1:",
        "ld1b z31.b, p0/z, [x1]",                                   // load avl bytes of plain-data

        "aese z31.b, z31.b,  z0.b", "aesmc z31.b, z31.b",           // perform AES-128 round 00 encryption
        "aese z31.b, z31.b,  z1.b", "aesmc z31.b, z31.b",           // perform AES-128 round 01 encryption
        "aese z31.b, z31.b,  z2.b", "aesmc z31.b, z31.b",           // perform AES-128 round 02 encryption
        "aese z31.b, z31.b,  z3.b", "aesmc z31.b, z31.b",           // perform AES-128 round 03 encryption
        "aese z31.b, z31.b,  z4.b", "aesmc z31.b, z31.b",           // perform AES-128 round 04 encryption
        "aese z31.b, z31.b,  z5.b", "aesmc z31.b, z31.b",           // perform AES-128 round 05 encryption
        "aese z31.b, z31.b,  z6.b", "aesmc z31.b, z31.b",           // perform AES-128 round 06 encryption
        "aese z31.b, z31.b,  z7.b", "aesmc z31.b, z31.b",           // perform AES-128 round 07 encryption
        "aese z31.b, z31.b,  z8.b", "aesmc z31.b, z31.b",           // perform AES-128 round 08 encryption
        "aese z31.b, z31.b,  z9.b",                                 // perform AES-128 round 09 encryption
        "eor  z31.b, z31.b, z10.b",                                 // perform AES-128 round 10 encryption

        "st1b z31.b, p0, [x0]",                                     // save avl bytes of cipher-data

        "incb x0", "incb x1", "incb x8",                            // increment plain-data pointer, cipher-data pointer, loop counter by avl indices

        "whilelt p0.b, x8, x2",                                     // set avl to len {x2} - loop counter {x8}, represented as a predicate
        "b.first 1b",                                               // loop if (0 < avl)
    "2:",
        "ret",
}
extern "C" {
    pub fn aes_armv9_encdec_aes128_encrypt(
        dst: *mut u8,
        src: *const u8,
        len: usize,
        key: *const u8,
    );
}

// TODO(silvanshade): switch to intrinsics when available
#[rustfmt::skip]
global_asm! {
    ".balign 8",                                                    // align section to 8 bytes
    ".global aes_armv9_encdec_aes128_decrypt",                      // declare symbol
    ".type aes_armv9_encdec_aes128_decrypt, %function",             // declare symbol as function type
    "aes_armv9_encdec_aes128_decrypt:",                             // start function
        "mov x8, #0",                                               // set loop counter {x8} to 0

        "whilelt p0.b, x8, x2",                                     // set avl to len {x2} - loop counter {x8}, represented as a predicate
        "b.none 2f",                                                // exit if avl == 0

        "ld1rqb {{ z0.b}}, p0/z, [x3, #0 ]",                        // broadcast load round 00 key
        "ld1rqb {{ z1.b}}, p0/z, [x3, #16]",                        // broadcast load round 01 key
        "ld1rqb {{ z2.b}}, p0/z, [x3, #32]",                        // broadcast load round 02 key
        "ld1rqb {{ z3.b}}, p0/z, [x3, #48]", "add x3, x3, #64",     // broadcast load round 03 key; increment key pointer by 4 indices
        "ld1rqb {{ z4.b}}, p0/z, [x3, #0 ]",                        // broadcast load round 04 key
        "ld1rqb {{ z5.b}}, p0/z, [x3, #16]",                        // broadcast load round 05 key
        "ld1rqb {{ z6.b}}, p0/z, [x3, #32]",                        // broadcast load round 06 key
        "ld1rqb {{ z7.b}}, p0/z, [x3, #48]", "add x3, x3, #64",     // broadcast load round 07 key; increment key pointer by 4 indices
        "ld1rqb {{ z8.b}}, p0/z, [x3, #0 ]",                        // broadcast load round 08 key
        "ld1rqb {{ z9.b}}, p0/z, [x3, #16]",                        // broadcast load round 09 key
        "ld1rqb {{z10.b}}, p0/z, [x3, #32]",                        // broadcast load round 10 key
    "1:",
        "ld1b z31.b, p0/z, [x1]",                                   // load vl bytes of cipher-data

        "aesd z31.b, z31.b, z10.b", "aesimc z31.b, z31.b",          // perform AES-128 round 10 decryption
        "aesd z31.b, z31.b,  z9.b", "aesimc z31.b, z31.b",          // perform AES-128 round 09 decryption
        "aesd z31.b, z31.b,  z8.b", "aesimc z31.b, z31.b",          // perform AES-128 round 08 decryption
        "aesd z31.b, z31.b,  z7.b", "aesimc z31.b, z31.b",          // perform AES-128 round 07 decryption
        "aesd z31.b, z31.b,  z6.b", "aesimc z31.b, z31.b",          // perform AES-128 round 06 decryption
        "aesd z31.b, z31.b,  z5.b", "aesimc z31.b, z31.b",          // perform AES-128 round 05 decryption
        "aesd z31.b, z31.b,  z4.b", "aesimc z31.b, z31.b",          // perform AES-128 round 04 decryption
        "aesd z31.b, z31.b,  z3.b", "aesimc z31.b, z31.b",          // perform AES-128 round 03 decryption
        "aesd z31.b, z31.b,  z2.b", "aesimc z31.b, z31.b",          // perform AES-128 round 02 decryption
        "aesd z31.b, z31.b,  z1.b",                                 // perform AES-128 round 01 decryption
        "eor  z31.b, z31.b,  z0.b",                                 // perform AES-128 round 00 decryption

        "st1b z31.b, p0, [x0]",                                     // save vl bytes of plain-data

        "incb x0", "incb x1", "incb x8",                            // increment plain-data pointer, cipher-data pointer, loop counter by avl indices

        "whilelt p0.b, x8, x2",                                     // set avl to len {x2} - loop counter {x8}, represented as a predicate
        "b.first 1b",                                               // loop if (0 < avl)
    "2:",
        "ret",
}
extern "C" {
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
pub(crate) fn encrypt1(keys: &RoundKeys<11>, mut data: InOut<'_, '_, Block>) {
    let data = unsafe {
        InOut::from_raw(
            data.get_in().as_ptr().cast::<Block>(),
            data.get_out().as_mut_ptr().cast::<Block>(),
        )
    };
    encrypt_vla(keys, data, 1)
}

#[inline(always)]
pub(crate) fn encrypt8(keys: &RoundKeys<11>, mut data: InOut<'_, '_, Block8>) {
    let data = unsafe {
        InOut::from_raw(
            data.get_in().as_ptr().cast::<Block>(),
            data.get_out().as_mut_ptr().cast::<Block>(),
        )
    };
    encrypt_vla(keys, data, 8)
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
pub(crate) fn decrypt1(keys: &RoundKeys<11>, mut data: InOut<'_, '_, Block>) {
    let data = unsafe {
        InOut::from_raw(
            data.get_in().as_ptr().cast::<Block>(),
            data.get_out().as_mut_ptr().cast::<Block>(),
        )
    };
    decrypt_vla(keys, data, 1)
}

#[inline(always)]
pub(crate) fn decrypt8(keys: &RoundKeys<11>, mut data: InOut<'_, '_, Block8>) {
    let data = unsafe {
        InOut::from_raw(
            data.get_in().as_ptr().cast::<Block>(),
            data.get_out().as_mut_ptr().cast::<Block>(),
        )
    };
    decrypt_vla(keys, data, 8)
}
