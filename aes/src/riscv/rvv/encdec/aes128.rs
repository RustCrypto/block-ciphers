use crate::{riscv::rvv::RoundKeys, Block, Block8};
use cipher::inout::InOut;
use core::arch::global_asm;

// TODO(silvanshade): switch to intrinsics when available
#[rustfmt::skip]
global_asm! {
    // INPUTS:
    //      a0:  uint8_t *      dst
    //      a1:  uint8_t *const src
    //      a2:   size_t        len
    //      a3: uint32_t *const key
    // SAFETY:
    //      - a0, a1 must be valid pointers to memory regions of at least len bytes
    //      - a3     must be valid pointers to memory regions of at least 176 bytes
    //      - on exit: a1 and a3 remain unchanged
    //      - on exit: a0 is overwritten with cipher-data
    ".balign 4",
    ".attribute arch, \"rv64gcv1p0_zkne_zknd_zvkned1p0\"",
    ".global aes_riscv_rv64_vector_encdec_aes128_encrypt",
    ".type aes_riscv_rv64_vector_encdec_aes128_encrypt, @function",
    "aes_riscv_rv64_vector_encdec_aes128_encrypt:",
        "andi t0, a2, -16",                     // t0 = len (round to multiple of 16)
        "beqz t0, 2f",                          // if len == 0, exit
        "srli t3, t0, 2",                       // t3 = len / 4

        "vsetivli zero, 4, e32, m1, ta, ma",    // configure RVV for vector shape: 4 x 32b x 1

        "vle32.v v10, (a3)", "addi a3, a3, 16", // load round 00 key
        "vle32.v v11, (a3)", "addi a3, a3, 16", // load round 01 key
        "vle32.v v12, (a3)", "addi a3, a3, 16", // load round 02 key
        "vle32.v v13, (a3)", "addi a3, a3, 16", // load round 03 key
        "vle32.v v14, (a3)", "addi a3, a3, 16", // load round 04 key
        "vle32.v v15, (a3)", "addi a3, a3, 16", // load round 05 key
        "vle32.v v16, (a3)", "addi a3, a3, 16", // load round 06 key
        "vle32.v v17, (a3)", "addi a3, a3, 16", // load round 07 key
        "vle32.v v18, (a3)", "addi a3, a3, 16", // load round 08 key
        "vle32.v v19, (a3)", "addi a3, a3, 16", // load round 09 key
        "vle32.v v20, (a3)",                    // load round 10 key
    "1:",
        "vsetvli t2, t3, e32, m1, ta, ma",      // configure RVV for vector shape: len x 32b x 1
                                                // t2 = vl4 <= len

        "vle32.v   v1, (a1)",                   // load vl bytes of plain-data
        "vaesz.vs  v1, v10",                    // perform AES-128 round 00 encryption
        "vaesem.vs v1, v11",                    // perform AES-128 round 01 encryption
        "vaesem.vs v1, v12",                    // perform AES-128 round 02 encryption
        "vaesem.vs v1, v13",                    // perform AES-128 round 03 encryption
        "vaesem.vs v1, v14",                    // perform AES-128 round 04 encryption
        "vaesem.vs v1, v15",                    // perform AES-128 round 05 encryption
        "vaesem.vs v1, v16",                    // perform AES-128 round 06 encryption
        "vaesem.vs v1, v17",                    // perform AES-128 round 07 encryption
        "vaesem.vs v1, v18",                    // perform AES-128 round 08 encryption
        "vaesem.vs v1, v19",                    // perform AES-128 round 09 encryption
        "vaesef.vs v1, v20",                    // perform AES-128 round 10 encryption
        "vse32.v   v1, (a0)",                   // save vl bytes of cipher-data

        "sub t3, t3, t2",                       // len  -= vl4      // vl (measuring  4-byte units)

        "slli t2, t2, 2",                       // vl16  = vl4 * 4  // vl (measuring 16-byte units)
        "add a1, a1, t2",                       // src  += vl16     // src += vl4 * 4
        "add a0, a0, t2",                       // dst  += vl16     // dst += vl4 * 4

        "bnez t3, 1b",                          // if len != 0, loop
    "2:",
        "ret",
}
extern "C" {
    fn aes_riscv_rv64_vector_encdec_aes128_encrypt(
        dst: *mut u8,
        src: *const u8,
        len: usize,
        key: *const u32,
    );
}

// TODO(silvanshade): switch to intrinsics when available
#[rustfmt::skip]
global_asm! {
    // INPUTS:
    //      a0:  uint8_t *      dst
    //      a1:  uint8_t *const src
    //      a2:   size_t        len
    //      a3: uint32_t *const key
    // SAFETY:
    //      - a0, a1 must be valid pointers to memory regions of at least len bytes
    //      - a3     must be valid pointers to memory regions of at least 176 bytes
    //      - on exit: a1, a3 are unchanged
    //      - on exit: a0 is overwritten with plain-data
    ".balign 4",
    ".attribute arch, \"rv64gcv1p0_zkne_zknd_zvkned1p0\"",
    ".global aes_riscv_rv64_vector_encdec_aes128_decrypt",
    ".type aes_riscv_rv64_vector_encdec_aes128_decrypt, @function",
    "aes_riscv_rv64_vector_encdec_aes128_decrypt:",
        "andi t0, a2, -16",                     // t0 = len (round to multiple of 16)
        "beqz t0, 2f",                          // if len == 0, exit
        "srli t3, t0, 2",                       // a2 = len / 4

        "vsetivli zero, 4, e32, m1, ta, ma",    // configure RVV for vector shape: 4 x 32b x 1

        "vle32.v v10, (a3)", "addi a3, a3, 16", // load round 00 key
        "vle32.v v11, (a3)", "addi a3, a3, 16", // load round 01 key
        "vle32.v v12, (a3)", "addi a3, a3, 16", // load round 02 key
        "vle32.v v13, (a3)", "addi a3, a3, 16", // load round 03 key
        "vle32.v v14, (a3)", "addi a3, a3, 16", // load round 04 key
        "vle32.v v15, (a3)", "addi a3, a3, 16", // load round 05 key
        "vle32.v v16, (a3)", "addi a3, a3, 16", // load round 06 key
        "vle32.v v17, (a3)", "addi a3, a3, 16", // load round 07 key
        "vle32.v v18, (a3)", "addi a3, a3, 16", // load round 08 key
        "vle32.v v19, (a3)", "addi a3, a3, 16", // load round 09 key
        "vle32.v v20, (a3)",                    // load round 10 key
    "1:",
        "vsetvli t2, t3, e32, m1, ta, ma",      // configure RVV for vector shape: len x 32b x 1
                                                // t2 = vl4 <= len

        "vle32.v   v0, (a1)",                   // load vl4 bytes of cipher-data
        "vaesz.vs  v0, v20",                    // perform AES-128 round 10 decryption
        "vaesdm.vs v0, v19",                    // perform AES-128 round 09 decryption
        "vaesdm.vs v0, v18",                    // perform AES-128 round 08 decryption
        "vaesdm.vs v0, v17",                    // perform AES-128 round 07 decryption
        "vaesdm.vs v0, v16",                    // perform AES-128 round 06 decryption
        "vaesdm.vs v0, v15",                    // perform AES-128 round 05 decryption
        "vaesdm.vs v0, v14",                    // perform AES-128 round 05 decryption
        "vaesdm.vs v0, v13",                    // perform AES-128 round 03 decryption
        "vaesdm.vs v0, v12",                    // perform AES-128 round 02 decryption
        "vaesdm.vs v0, v11",                    // perform AES-128 round 01 decryption
        "vaesdf.vs v0, v10",                    // perform AES-128 round 00 decryption
        "vse32.v   v0, (a0)",                   // save vl4 bytes of plain-data

        "sub t3, t3, t2",                       // len  -= vl4      // vl (measuring  4-byte units)

        "slli t2, t2, 2",                       // vl16  = vl4 * 4  // vl (measuring 16-byte units)
        "add a1, a1, t2",                       // src  += vl16     // src += vl4 * 4
        "add a0, a0, t2",                       // dst  += vl16     // dst += vl4 * 4

        "bnez t3, 1b",                          // if len != 0, loop
    "2:",
        "ret",
}
extern "C" {
    fn aes_riscv_rv64_vector_encdec_aes128_decrypt(
        dst: *mut u8,
        src: *const u8,
        len: usize,
        key: *const u32,
    );
}

#[inline(always)]
fn encrypt_vla(keys: &RoundKeys<11>, mut data: InOut<'_, '_, Block>, blocks: usize) {
    let dst = data.get_out().as_mut_ptr();
    let src = data.get_in().as_ptr();
    let len = blocks * 16;
    let key = keys.as_ptr().cast::<u32>();
    unsafe { aes_riscv_rv64_vector_encdec_aes128_encrypt(dst, src, len, key) };
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
fn decrypt_vla(keys: &RoundKeys<11>, mut data: InOut<'_, '_, Block>, blocks: usize) {
    let dst = data.get_out().as_mut_ptr();
    let src = data.get_in().as_ptr();
    let len = blocks * 16;
    let key = keys.as_ptr().cast::<u32>();
    unsafe { aes_riscv_rv64_vector_encdec_aes128_decrypt(dst, src, len, key) };
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
