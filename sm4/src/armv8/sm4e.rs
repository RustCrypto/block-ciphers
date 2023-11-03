//! SM4 implementation with SM4 extension instruction set
//!
//! Implementation is from <https://github.com/randombit/botan> and Linux kernel arch/arm64/crypto/sm4-ce-core.S

#![allow(unsafe_code)]

#[cfg(feature = "zeroize")]
use cipher::zeroize::ZeroizeOnDrop;
use cipher::{
    consts::{U16, U4, U8},
    generic_array::GenericArray,
    inout::{InOut, InOutBuf},
    AlgorithmName, Block, BlockCipher, BlockDecrypt, BlockSizeUser, Key, KeyInit, KeySizeUser,
    ParBlocks, ParBlocksSizeUser, Unsigned,
};
use cipher::{BlockBackend, BlockEncrypt};
use core::{arch::aarch64::*, fmt};

use crate::consts::{CK, FK};

#[inline]
#[target_feature(enable = "sm4")]
pub(crate) unsafe fn sm4_init_key<T: KeySizeUser>(key: &Key<T>) -> [u32; 32] {
    let mut mk: uint8x16_t = vld1q_u8(key.as_ptr() as *const _);
    mk = vrev32q_u8(mk);
    let fk: uint8x16_t = vld1q_u8(FK.as_ptr() as *const _);

    let ck0 = vld1q_u32(CK.as_ptr().add(0));
    let ck1 = vld1q_u32(CK.as_ptr().add(4));
    let ck2 = vld1q_u32(CK.as_ptr().add(8));
    let ck3 = vld1q_u32(CK.as_ptr().add(12));
    let ck4 = vld1q_u32(CK.as_ptr().add(16));
    let ck5 = vld1q_u32(CK.as_ptr().add(20));
    let ck6 = vld1q_u32(CK.as_ptr().add(24));
    let ck7 = vld1q_u32(CK.as_ptr().add(28));

    // input ^ mk
    let rk = vreinterpretq_u32_u8(veorq_u8(mk, fk));

    let k0 = super::intrinsics::vsm4ekeyq_u32(rk, ck0);
    let k1 = super::intrinsics::vsm4ekeyq_u32(k0, ck1);
    let k2 = super::intrinsics::vsm4ekeyq_u32(k1, ck2);
    let k3 = super::intrinsics::vsm4ekeyq_u32(k2, ck3);
    let k4 = super::intrinsics::vsm4ekeyq_u32(k3, ck4);
    let k5 = super::intrinsics::vsm4ekeyq_u32(k4, ck5);
    let k6 = super::intrinsics::vsm4ekeyq_u32(k5, ck6);
    let k7 = super::intrinsics::vsm4ekeyq_u32(k6, ck7);

    let mut rkey = [0u32; 32];
    vst1q_u32(rkey.as_mut_ptr().add(0), k0);
    vst1q_u32(rkey.as_mut_ptr().add(4), k1);
    vst1q_u32(rkey.as_mut_ptr().add(8), k2);
    vst1q_u32(rkey.as_mut_ptr().add(12), k3);
    vst1q_u32(rkey.as_mut_ptr().add(16), k4);
    vst1q_u32(rkey.as_mut_ptr().add(20), k5);
    vst1q_u32(rkey.as_mut_ptr().add(24), k6);
    vst1q_u32(rkey.as_mut_ptr().add(28), k7);

    rkey
}

#[inline]
unsafe fn qswap_32(b: uint32x4_t) -> uint32x4_t {
    static QSWAP_TBL: [u8; 16] = [12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3];
    vreinterpretq_u32_u8(vqtbl1q_u8(
        vreinterpretq_u8_u32(b),
        vld1q_u8(QSWAP_TBL.as_ptr()),
    ))
}

#[inline]
unsafe fn bswap_32(b: uint32x4_t) -> uint32x4_t {
    vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(b)))
}

/// Swap both the quad-words and bytes within each word
/// equivalent to return bswap_32(qswap_32(B))
#[inline]
unsafe fn bqswap_32(b: uint32x4_t) -> uint32x4_t {
    static BSWAP_TBL: [u8; 16] = [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0];
    return vreinterpretq_u32_u8(vqtbl1q_u8(
        vreinterpretq_u8_u32(b),
        vld1q_u8(BSWAP_TBL.as_ptr()),
    ));
}

macro_rules! sm4_e {
    ($($b:ident),+ @ $k:expr) => {
        $(
            $b = super::intrinsics::vsm4eq_u32($b, $k);
        )+
    }
}

type ParBlocks4<T> = GenericArray<Block<T>, U4>;
type ParBlocks8<T> = GenericArray<Block<T>, U8>;

#[inline]
#[target_feature(enable = "sm4")]
pub(super) unsafe fn sm4_encrypt4<T: BlockSizeUser>(
    blocks: InOut<'_, '_, ParBlocks4<T>>,
    rk: &[uint32x4_t; 8],
) {
    let (in_ptr, out_ptr) = blocks.into_raw();
    let input32 = in_ptr as *const u32;
    let output32 = out_ptr as *mut u32;

    let mut b0 = bswap_32(vld1q_u32(input32.add(0)));
    let mut b1 = bswap_32(vld1q_u32(input32.add(4)));
    let mut b2 = bswap_32(vld1q_u32(input32.add(8)));
    let mut b3 = bswap_32(vld1q_u32(input32.add(12)));

    sm4_e!(b0, b1, b2, b3 @ rk[0]);
    sm4_e!(b0, b1, b2, b3 @ rk[1]);
    sm4_e!(b0, b1, b2, b3 @ rk[2]);
    sm4_e!(b0, b1, b2, b3 @ rk[3]);
    sm4_e!(b0, b1, b2, b3 @ rk[4]);
    sm4_e!(b0, b1, b2, b3 @ rk[5]);
    sm4_e!(b0, b1, b2, b3 @ rk[6]);
    sm4_e!(b0, b1, b2, b3 @ rk[7]);

    vst1q_u32(output32.add(0), bqswap_32(b0));
    vst1q_u32(output32.add(4), bqswap_32(b1));
    vst1q_u32(output32.add(8), bqswap_32(b2));
    vst1q_u32(output32.add(12), bqswap_32(b3));
}

#[inline]
#[target_feature(enable = "sm4")]
pub(super) unsafe fn sm4_encrypt8<T: BlockSizeUser>(
    blocks: InOut<'_, '_, ParBlocks8<T>>,
    rk: &[uint32x4_t; 8],
) {
    let (in_ptr, out_ptr) = blocks.into_raw();
    let input32 = in_ptr as *const u32;
    let output32 = out_ptr as *mut u32;

    let mut b0 = bswap_32(vld1q_u32(input32.add(0)));
    let mut b1 = bswap_32(vld1q_u32(input32.add(4)));
    let mut b2 = bswap_32(vld1q_u32(input32.add(8)));
    let mut b3 = bswap_32(vld1q_u32(input32.add(12)));
    let mut b4 = bswap_32(vld1q_u32(input32.add(16)));
    let mut b5 = bswap_32(vld1q_u32(input32.add(20)));
    let mut b6 = bswap_32(vld1q_u32(input32.add(24)));
    let mut b7 = bswap_32(vld1q_u32(input32.add(28)));

    sm4_e!(b0, b1, b2, b3, b4, b5, b6, b7 @ rk[0]);
    sm4_e!(b0, b1, b2, b3, b4, b5, b6, b7 @ rk[1]);
    sm4_e!(b0, b1, b2, b3, b4, b5, b6, b7 @ rk[2]);
    sm4_e!(b0, b1, b2, b3, b4, b5, b6, b7 @ rk[3]);
    sm4_e!(b0, b1, b2, b3, b4, b5, b6, b7 @ rk[4]);
    sm4_e!(b0, b1, b2, b3, b4, b5, b6, b7 @ rk[5]);
    sm4_e!(b0, b1, b2, b3, b4, b5, b6, b7 @ rk[6]);
    sm4_e!(b0, b1, b2, b3, b4, b5, b6, b7 @ rk[7]);

    vst1q_u32(output32.add(0), bqswap_32(b0));
    vst1q_u32(output32.add(4), bqswap_32(b1));
    vst1q_u32(output32.add(8), bqswap_32(b2));
    vst1q_u32(output32.add(12), bqswap_32(b3));
    vst1q_u32(output32.add(16), bqswap_32(b4));
    vst1q_u32(output32.add(20), bqswap_32(b5));
    vst1q_u32(output32.add(24), bqswap_32(b6));
    vst1q_u32(output32.add(28), bqswap_32(b7));
}

#[inline]
#[target_feature(enable = "sm4")]
pub(super) unsafe fn sm4_encrypt1<T: BlockSizeUser>(
    block: InOut<'_, '_, Block<T>>,
    rk: &[uint32x4_t; 8],
) {
    let (in_ptr, out_ptr) = block.into_raw();
    let input32 = in_ptr as *const u32;
    let output32 = out_ptr as *mut u32;

    let mut b = bswap_32(vld1q_u32(input32));

    sm4_e!(b @ rk[0]);
    sm4_e!(b @ rk[1]);
    sm4_e!(b @ rk[2]);
    sm4_e!(b @ rk[3]);
    sm4_e!(b @ rk[4]);
    sm4_e!(b @ rk[5]);
    sm4_e!(b @ rk[6]);
    sm4_e!(b @ rk[7]);

    vst1q_u32(output32, bqswap_32(b));
}

#[inline]
#[target_feature(enable = "sm4")]
pub(super) unsafe fn sm4_decrypt4<T: BlockSizeUser>(
    blocks: InOut<'_, '_, ParBlocks4<T>>,
    rk: &[uint32x4_t; 8],
) {
    let (in_ptr, out_ptr) = blocks.into_raw();
    let input32 = in_ptr as *const u32;
    let output32 = out_ptr as *mut u32;

    let mut b0 = bswap_32(vld1q_u32(input32.add(0)));
    let mut b1 = bswap_32(vld1q_u32(input32.add(4)));
    let mut b2 = bswap_32(vld1q_u32(input32.add(8)));
    let mut b3 = bswap_32(vld1q_u32(input32.add(12)));

    sm4_e!(b0, b1, b2, b3 @ rk[7]);
    sm4_e!(b0, b1, b2, b3 @ rk[6]);
    sm4_e!(b0, b1, b2, b3 @ rk[5]);
    sm4_e!(b0, b1, b2, b3 @ rk[4]);
    sm4_e!(b0, b1, b2, b3 @ rk[3]);
    sm4_e!(b0, b1, b2, b3 @ rk[2]);
    sm4_e!(b0, b1, b2, b3 @ rk[1]);
    sm4_e!(b0, b1, b2, b3 @ rk[0]);

    vst1q_u32(output32.add(0), bqswap_32(b0));
    vst1q_u32(output32.add(4), bqswap_32(b1));
    vst1q_u32(output32.add(8), bqswap_32(b2));
    vst1q_u32(output32.add(12), bqswap_32(b3));
}

#[inline]
#[target_feature(enable = "sm4")]
pub(super) unsafe fn sm4_decrypt8<T: BlockSizeUser>(
    blocks: InOut<'_, '_, ParBlocks8<T>>,
    rk: &[uint32x4_t; 8],
) {
    let (in_ptr, out_ptr) = blocks.into_raw();
    let input32 = in_ptr as *const u32;
    let output32 = out_ptr as *mut u32;

    let mut b0 = bswap_32(vld1q_u32(input32.add(0)));
    let mut b1 = bswap_32(vld1q_u32(input32.add(4)));
    let mut b2 = bswap_32(vld1q_u32(input32.add(8)));
    let mut b3 = bswap_32(vld1q_u32(input32.add(12)));
    let mut b4 = bswap_32(vld1q_u32(input32.add(16)));
    let mut b5 = bswap_32(vld1q_u32(input32.add(20)));
    let mut b6 = bswap_32(vld1q_u32(input32.add(24)));
    let mut b7 = bswap_32(vld1q_u32(input32.add(28)));

    sm4_e!(b0, b1, b2, b3, b4, b5, b6, b7 @ rk[7]);
    sm4_e!(b0, b1, b2, b3, b4, b5, b6, b7 @ rk[6]);
    sm4_e!(b0, b1, b2, b3, b4, b5, b6, b7 @ rk[5]);
    sm4_e!(b0, b1, b2, b3, b4, b5, b6, b7 @ rk[4]);
    sm4_e!(b0, b1, b2, b3, b4, b5, b6, b7 @ rk[3]);
    sm4_e!(b0, b1, b2, b3, b4, b5, b6, b7 @ rk[2]);
    sm4_e!(b0, b1, b2, b3, b4, b5, b6, b7 @ rk[1]);
    sm4_e!(b0, b1, b2, b3, b4, b5, b6, b7 @ rk[0]);

    vst1q_u32(output32.add(0), bqswap_32(b0));
    vst1q_u32(output32.add(4), bqswap_32(b1));
    vst1q_u32(output32.add(8), bqswap_32(b2));
    vst1q_u32(output32.add(12), bqswap_32(b3));
    vst1q_u32(output32.add(16), bqswap_32(b4));
    vst1q_u32(output32.add(20), bqswap_32(b5));
    vst1q_u32(output32.add(24), bqswap_32(b6));
    vst1q_u32(output32.add(28), bqswap_32(b7));
}

#[inline]
#[target_feature(enable = "sm4")]
pub(super) unsafe fn sm4_decrypt1<T: BlockSizeUser>(
    block: InOut<'_, '_, Block<T>>,
    rk: &[uint32x4_t; 8],
) {
    let (in_ptr, out_ptr) = block.into_raw();
    let input32 = in_ptr as *const u32;
    let output32 = out_ptr as *mut u32;

    let mut b = bswap_32(vld1q_u32(input32));

    sm4_e!(b @ rk[7]);
    sm4_e!(b @ rk[6]);
    sm4_e!(b @ rk[5]);
    sm4_e!(b @ rk[4]);
    sm4_e!(b @ rk[3]);
    sm4_e!(b @ rk[2]);
    sm4_e!(b @ rk[1]);
    sm4_e!(b @ rk[0]);

    vst1q_u32(output32, bqswap_32(b));
}

/// SM4 block cipher.
#[derive(Clone)]
pub struct Sm4 {
    erk: [uint32x4_t; 8],
    drk: [uint32x4_t; 8],
}

impl BlockCipher for Sm4 {}

impl KeySizeUser for Sm4 {
    type KeySize = U16;
}

impl KeyInit for Sm4 {
    fn new(key: &Key<Self>) -> Self {
        unsafe {
            let rk = sm4_init_key::<Self>(key);

            let erk = [
                vld1q_u32(rk.as_ptr().add(0)),
                vld1q_u32(rk.as_ptr().add(4)),
                vld1q_u32(rk.as_ptr().add(8)),
                vld1q_u32(rk.as_ptr().add(12)),
                vld1q_u32(rk.as_ptr().add(16)),
                vld1q_u32(rk.as_ptr().add(20)),
                vld1q_u32(rk.as_ptr().add(24)),
                vld1q_u32(rk.as_ptr().add(28)),
            ];

            let drk = [
                qswap_32(erk[0]),
                qswap_32(erk[1]),
                qswap_32(erk[2]),
                qswap_32(erk[3]),
                qswap_32(erk[4]),
                qswap_32(erk[5]),
                qswap_32(erk[6]),
                qswap_32(erk[7]),
            ];

            Sm4 { erk, drk }
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
        unsafe {
            for i in 0..self.erk.len() {
                self.erk[i] = veorq_u32(self.erk[i], self.erk[i]);
            }
            for i in 0..self.drk.len() {
                self.drk[i] = veorq_u32(self.drk[i], self.drk[i]);
            }
        }
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
    type ParBlocksSize = U8;
}

impl<'a> BlockBackend for Sm4Enc<'a> {
    #[inline(always)]
    fn proc_block(&mut self, block: InOut<'_, '_, Block<Self>>) {
        unsafe { sm4_encrypt1::<Self>(block, &self.0.erk) }
    }

    #[inline(always)]
    fn proc_tail_blocks(&mut self, blocks: InOutBuf<'_, '_, Block<Self>>) {
        assert!(blocks.len() < Self::ParBlocksSize::USIZE);

        let (chunks, tail) = blocks.into_chunks::<U4>();
        for chunk in chunks {
            unsafe { sm4_encrypt4::<Self>(chunk, &self.0.erk) }
        }

        for block in tail {
            self.proc_block(block);
        }
    }

    #[inline(always)]
    fn proc_par_blocks(&mut self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
        unsafe { sm4_encrypt8::<Self>(blocks, &self.0.erk) }
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
    type ParBlocksSize = U8;
}

impl<'a> BlockBackend for Sm4Dec<'a> {
    #[inline(always)]
    fn proc_block(&mut self, block: InOut<'_, '_, Block<Self>>) {
        unsafe { sm4_decrypt1::<Self>(block, &self.0.drk) }
    }

    #[inline(always)]
    fn proc_tail_blocks(&mut self, blocks: InOutBuf<'_, '_, Block<Self>>) {
        assert!(blocks.len() < Self::ParBlocksSize::USIZE);

        let (chunks, tail) = blocks.into_chunks::<U4>();
        for chunk in chunks {
            unsafe { sm4_decrypt4::<Self>(chunk, &self.0.drk) }
        }

        for block in tail {
            self.proc_block(block);
        }
    }

    #[inline(always)]
    fn proc_par_blocks(&mut self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
        unsafe { sm4_decrypt8::<Self>(blocks, &self.0.drk) }
    }
}
