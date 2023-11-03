//! SM4 NEON
//!
//! From Linux kernel arch/arm64/crypto/sm4-neon-core.S

#![allow(unsafe_code)]

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};
use cipher::{
    consts::{U16, U4},
    generic_array::GenericArray,
    inout::InOut,
    AlgorithmName, Block, BlockCipher, BlockDecrypt, BlockSizeUser, Key, KeyInit, KeySizeUser,
    ParBlocks, ParBlocksSizeUser,
};
use cipher::{BlockBackend, BlockEncrypt};
use core::{arch::aarch64::*, fmt};

use crate::consts::SBOX;

type ParBlocks4<T> = GenericArray<Block<T>, U4>;

#[inline]
#[target_feature(enable = "neon")]
unsafe fn sbox_table_lookup(
    sbox_table: &[uint8x16x4_t; 4],
    b: uint32x4_t,
    dec: uint8x16_t,
) -> uint32x4_t {
    let b0 = vreinterpretq_u8_u32(b);
    let r0 = vqtbl4q_u8(sbox_table[0], b0);

    let b1 = vsubq_u8(b0, dec);
    let r1 = vqtbl4q_u8(sbox_table[1], b1);

    let b2 = vsubq_u8(b1, dec);
    let r2 = vqtbl4q_u8(sbox_table[2], b2);

    let b3 = vsubq_u8(b2, dec);
    let r3 = vqtbl4q_u8(sbox_table[3], b3);

    // Join results
    vreinterpretq_u32_u8(veorq_u8(veorq_u8(veorq_u8(r0, r1), r2), r3))
}

#[inline]
#[target_feature(enable = "neon")]
pub(super) unsafe fn sm4_process4<T: BlockSizeUser>(
    blocks: InOut<'_, '_, ParBlocks4<T>>,
    rk: &[u32; 32],
    encrypt: bool,
) {
    // SBox
    let sbox_table: [uint8x16x4_t; 4] = [
        uint8x16x4_t(
            vld1q_u8(SBOX.as_ptr().add(64 * 0 + 16 * 0)),
            vld1q_u8(SBOX.as_ptr().add(64 * 0 + 16 * 1)),
            vld1q_u8(SBOX.as_ptr().add(64 * 0 + 16 * 2)),
            vld1q_u8(SBOX.as_ptr().add(64 * 0 + 16 * 3)),
        ),
        uint8x16x4_t(
            vld1q_u8(SBOX.as_ptr().add(64 * 1 + 16 * 0)),
            vld1q_u8(SBOX.as_ptr().add(64 * 1 + 16 * 1)),
            vld1q_u8(SBOX.as_ptr().add(64 * 1 + 16 * 2)),
            vld1q_u8(SBOX.as_ptr().add(64 * 1 + 16 * 3)),
        ),
        uint8x16x4_t(
            vld1q_u8(SBOX.as_ptr().add(64 * 2 + 16 * 0)),
            vld1q_u8(SBOX.as_ptr().add(64 * 2 + 16 * 1)),
            vld1q_u8(SBOX.as_ptr().add(64 * 2 + 16 * 2)),
            vld1q_u8(SBOX.as_ptr().add(64 * 2 + 16 * 3)),
        ),
        uint8x16x4_t(
            vld1q_u8(SBOX.as_ptr().add(64 * 3 + 16 * 0)),
            vld1q_u8(SBOX.as_ptr().add(64 * 3 + 16 * 1)),
            vld1q_u8(SBOX.as_ptr().add(64 * 3 + 16 * 2)),
            vld1q_u8(SBOX.as_ptr().add(64 * 3 + 16 * 3)),
        ),
    ];

    // Load data, 4 blocks
    let (in_ptr, out_ptr) = blocks.into_raw();
    let mut x: uint32x4x4_t = vld4q_u32(in_ptr as *const _);

    static SUB_DATA: [u8; 16] = [
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    ];

    // Index -64 for SBox table lookup
    let dec = vld1q_u8(SUB_DATA.as_ptr());

    // Reverse every 8bits in each blocks
    x.0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(x.0)));
    x.1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(x.1)));
    x.2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(x.2)));
    x.3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(x.3)));

    // Process loop
    for i in 0..32 {
        // x1 xor x2 xor x3 xor rk[i]
        let mut b = if encrypt {
            vdupq_n_u32(rk[i])
        } else {
            vdupq_n_u32(rk[31 - i])
        };
        b = veorq_u32(b, x.1);
        b = veorq_u32(b, x.2);
        b = veorq_u32(b, x.3);

        // SBox lookup
        b = sbox_table_lookup(&sbox_table, b, dec);
        x.0 = veorq_u32(x.0, b);

        let t1 = vshlq_n_u32(b, 2);
        let t2 = vshrq_n_u32(b, 32 - 2);
        let t3 = veorq_u32(t1, t2);
        x.0 = veorq_u32(x.0, t3);

        let t1 = vshlq_n_u32(b, 10);
        let t2 = vshrq_n_u32(b, 32 - 10);
        let t3 = veorq_u32(t1, t2);
        x.0 = veorq_u32(x.0, t3);

        let t1 = vshlq_n_u32(b, 18);
        let t2 = vshrq_n_u32(b, 32 - 18);
        let t3 = veorq_u32(t1, t2);
        x.0 = veorq_u32(x.0, t3);

        let t1 = vshlq_n_u32(b, 24);
        let t2 = vshrq_n_u32(b, 32 - 24);
        let t3 = veorq_u32(t1, t2);
        x.0 = veorq_u32(x.0, t3);

        b = x.0;
        x.0 = x.1;
        x.1 = x.2;
        x.2 = x.3;
        x.3 = b;
    }

    // Reverse result blocks
    let b0 = x.0;
    x.0 = x.3;
    x.3 = b0;
    let b1 = x.1;
    x.1 = x.2;
    x.2 = b1;

    // Reverse 8bits in blocks
    x.0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(x.0)));
    x.1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(x.1)));
    x.2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(x.2)));
    x.3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(x.3)));

    vst4q_u32(out_ptr as *mut _, x);
}

/// SM4 block cipher.
#[derive(Clone)]
pub struct Sm4 {
    rk: [u32; 32],
}

impl BlockCipher for Sm4 {}

impl KeySizeUser for Sm4 {
    type KeySize = U16;
}

impl KeyInit for Sm4 {
    fn new(key: &Key<Self>) -> Self {
        Sm4 {
            rk: crate::soft::sm4_init_key::<Self>(key),
        }
    }
}

impl fmt::Debug for Sm4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sm4 { ... }")
    }
}

impl AlgorithmName for Sm4 {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sm4")
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl Drop for Sm4 {
    fn drop(&mut self) {
        self.rk.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl ZeroizeOnDrop for Sm4 {}

impl BlockSizeUser for Sm4 {
    type BlockSize = U16;
}

impl BlockEncrypt for Sm4 {
    fn encrypt_with_backend(&self, f: impl cipher::BlockClosure<BlockSize = Self::BlockSize>) {
        f.call(&mut Sm4Enc(self))
    }
}

pub struct Sm4Enc<'a>(&'a Sm4);

impl<'a> BlockSizeUser for Sm4Enc<'a> {
    type BlockSize = U16;
}

impl<'a> ParBlocksSizeUser for Sm4Enc<'a> {
    type ParBlocksSize = U4;
}

impl<'a> BlockBackend for Sm4Enc<'a> {
    #[inline(always)]
    fn proc_block(&mut self, block: InOut<'_, '_, Block<Self>>) {
        crate::soft::sm4_encrypt::<Self>(block, &self.0.rk);
    }

    #[inline(always)]
    fn proc_par_blocks(&mut self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
        unsafe { sm4_process4::<Self>(blocks, &self.0.rk, true) }
    }
}

impl BlockDecrypt for Sm4 {
    fn decrypt_with_backend(&self, f: impl cipher::BlockClosure<BlockSize = Self::BlockSize>) {
        f.call(&mut Sm4Dec(self))
    }
}

pub struct Sm4Dec<'a>(&'a Sm4);

impl<'a> BlockSizeUser for Sm4Dec<'a> {
    type BlockSize = U16;
}

impl<'a> ParBlocksSizeUser for Sm4Dec<'a> {
    type ParBlocksSize = U4;
}

impl<'a> BlockBackend for Sm4Dec<'a> {
    #[inline(always)]
    fn proc_block(&mut self, block: InOut<'_, '_, Block<Self>>) {
        crate::soft::sm4_decrypt::<Self>(block, &self.0.rk);
    }

    #[inline(always)]
    fn proc_par_blocks(&mut self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
        unsafe { sm4_process4::<Self>(blocks, &self.0.rk, false) }
    }
}
