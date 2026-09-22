//! SM4 with X86 AES-NI instruction set
//!
//! Implementation was borrowed from <https://www.cnblogs.com/kentle/p/15826075.html> by kentle.

#![allow(unsafe_code, unsafe_op_in_unsafe_fn)]

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};
use cipher::{
    AlgorithmName, Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, InOut, Key,
    KeyInit, KeySizeUser, ParBlocks, ParBlocksSizeUser,
    consts::{U4, U16},
};
use core::{arch::x86_64::*, fmt};

#[inline]
unsafe fn mm_pack0_epi32(a: __m128i, b: __m128i, c: __m128i, d: __m128i) -> __m128i {
    _mm_unpacklo_epi64(_mm_unpacklo_epi32(a, b), _mm_unpacklo_epi32(c, d))
}

#[inline]
unsafe fn mm_pack1_epi32(a: __m128i, b: __m128i, c: __m128i, d: __m128i) -> __m128i {
    _mm_unpackhi_epi64(_mm_unpacklo_epi32(a, b), _mm_unpacklo_epi32(c, d))
}

#[inline]
unsafe fn mm_pack2_epi32(a: __m128i, b: __m128i, c: __m128i, d: __m128i) -> __m128i {
    _mm_unpacklo_epi64(_mm_unpackhi_epi32(a, b), _mm_unpackhi_epi32(c, d))
}

#[inline]
unsafe fn mm_pack3_epi32(a: __m128i, b: __m128i, c: __m128i, d: __m128i) -> __m128i {
    _mm_unpackhi_epi64(_mm_unpackhi_epi32(a, b), _mm_unpackhi_epi32(c, d))
}

#[inline]
unsafe fn mm_xor2(a: __m128i, b: __m128i) -> __m128i {
    _mm_xor_si128(a, b)
}

#[inline]
unsafe fn mm_xor3(a: __m128i, b: __m128i, c: __m128i) -> __m128i {
    mm_xor2(a, mm_xor2(b, c))
}

#[inline]
unsafe fn mm_xor4(a: __m128i, b: __m128i, c: __m128i, d: __m128i) -> __m128i {
    mm_xor2(a, mm_xor3(b, c, d))
}

#[inline]
unsafe fn mm_xor5(a: __m128i, b: __m128i, c: __m128i, d: __m128i, e: __m128i) -> __m128i {
    mm_xor2(a, mm_xor4(b, c, d, e))
}

#[inline]
unsafe fn mm_xor6(
    a: __m128i,
    b: __m128i,
    c: __m128i,
    d: __m128i,
    e: __m128i,
    f: __m128i,
) -> __m128i {
    mm_xor2(a, mm_xor5(b, c, d, e, f))
}

macro_rules! mm_rotl_epi32 {
    ($a:expr, $n:literal) => {
        mm_xor2(_mm_slli_epi32::<$n>($a), _mm_srli_epi32::<{ 32 - $n }>($a))
    };
}

#[inline]
unsafe fn mul_matrix(x: __m128i, higher_mask: __m128i, lower_mask: __m128i) -> __m128i {
    let and_mask = _mm_set1_epi32(0x0f0f0f0f);
    let mut tmp2 = _mm_srli_epi16(x, 4);
    let mut tmp1 = _mm_and_si128(x, and_mask);
    tmp2 = _mm_and_si128(tmp2, and_mask);
    tmp1 = _mm_shuffle_epi8(lower_mask, tmp1);
    tmp2 = _mm_shuffle_epi8(higher_mask, tmp2);
    _mm_xor_si128(tmp1, tmp2)
}

#[inline]
unsafe fn mul_matrix_ata(x: __m128i) -> __m128i {
    let higher_mask = _mm_set_epi8(
        0x14u8 as i8,
        0x07u8 as i8,
        0xc6u8 as i8,
        0xd5u8 as i8,
        0x6cu8 as i8,
        0x7fu8 as i8,
        0xbeu8 as i8,
        0xadu8 as i8,
        0xb9u8 as i8,
        0xaau8 as i8,
        0x6bu8 as i8,
        0x78u8 as i8,
        0xc1u8 as i8,
        0xd2u8 as i8,
        0x13u8 as i8,
        0x00u8 as i8,
    );
    let lower_mask = _mm_set_epi8(
        0xd8u8 as i8,
        0xb8u8 as i8,
        0xfau8 as i8,
        0x9au8 as i8,
        0xc5u8 as i8,
        0xa5u8 as i8,
        0xe7u8 as i8,
        0x87u8 as i8,
        0x5fu8 as i8,
        0x3fu8 as i8,
        0x7du8 as i8,
        0x1du8 as i8,
        0x42u8 as i8,
        0x22u8 as i8,
        0x60u8 as i8,
        0x00u8 as i8,
    );
    mul_matrix(x, higher_mask, lower_mask)
}

#[inline]
unsafe fn mul_matrix_ta(x: __m128i) -> __m128i {
    let higher_mask = _mm_set_epi8(
        0x22u8 as i8,
        0x58u8 as i8,
        0x1au8 as i8,
        0x60u8 as i8,
        0x02u8 as i8,
        0x78u8 as i8,
        0x3au8 as i8,
        0x40u8 as i8,
        0x62u8 as i8,
        0x18u8 as i8,
        0x5au8 as i8,
        0x20u8 as i8,
        0x42u8 as i8,
        0x38u8 as i8,
        0x7au8 as i8,
        0x00u8 as i8,
    );
    let lower_mask = _mm_set_epi8(
        0xe2u8 as i8,
        0x28u8 as i8,
        0x95u8 as i8,
        0x5fu8 as i8,
        0x69u8 as i8,
        0xa3u8 as i8,
        0x1eu8 as i8,
        0xd4u8 as i8,
        0x36u8 as i8,
        0xfcu8 as i8,
        0x41u8 as i8,
        0x8bu8 as i8,
        0xbdu8 as i8,
        0x77u8 as i8,
        0xcau8 as i8,
        0x00u8 as i8,
    );
    mul_matrix(x, higher_mask, lower_mask)
}

#[inline]
unsafe fn add_tc(x: __m128i) -> __m128i {
    let tc = _mm_set1_epi8(0b00100011);
    _mm_xor_si128(x, tc)
}

#[inline]
unsafe fn add_atac(x: __m128i) -> __m128i {
    let atac = _mm_set1_epi8(0b00111011);
    _mm_xor_si128(x, atac)
}

#[inline]
unsafe fn sm4_sbox(mut x: __m128i) -> __m128i {
    let mask: __m128i = _mm_set_epi8(
        0x03, 0x06, 0x09, 0x0c, 0x0f, 0x02, 0x05, 0x08, 0x0b, 0x0e, 0x01, 0x04, 0x07, 0x0a, 0x0d,
        0x00,
    );
    x = _mm_shuffle_epi8(x, mask); // 逆行移位
    x = add_tc(mul_matrix_ta(x));
    x = _mm_aesenclast_si128(x, _mm_setzero_si128());
    add_atac(mul_matrix_ata(x))
}

#[inline]
#[target_feature(enable = "aes")]
pub(super) unsafe fn sm4_process4<T: ParBlocksSizeUser>(
    blocks: InOut<'_, '_, ParBlocks<T>>,
    rk: &[u32; 32],
    encrypt: bool,
) {
    let (in_ptr, out_ptr) = blocks.into_raw();

    let in_block_ptr: *const __m128i = in_ptr as *const _;
    let mut b: [__m128i; 4] = [
        _mm_loadu_si128(in_block_ptr.add(0)),
        _mm_loadu_si128(in_block_ptr.add(1)),
        _mm_loadu_si128(in_block_ptr.add(2)),
        _mm_loadu_si128(in_block_ptr.add(3)),
    ];
    let vindex = _mm_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);

    let mut x: [__m128i; 4] = [
        mm_pack0_epi32(b[0], b[1], b[2], b[3]),
        mm_pack1_epi32(b[0], b[1], b[2], b[3]),
        mm_pack2_epi32(b[0], b[1], b[2], b[3]),
        mm_pack3_epi32(b[0], b[1], b[2], b[3]),
    ];

    // Shuffle Endian
    x[0] = _mm_shuffle_epi8(x[0], vindex);
    x[1] = _mm_shuffle_epi8(x[1], vindex);
    x[2] = _mm_shuffle_epi8(x[2], vindex);
    x[3] = _mm_shuffle_epi8(x[3], vindex);

    for i in 0..32 {
        let k = if encrypt {
            _mm_set1_epi32(rk[i] as i32)
        } else {
            _mm_set1_epi32(rk[31 - i] as i32)
        };
        b[0] = mm_xor4(x[1], x[2], x[3], k);
        b[0] = sm4_sbox(b[0]);
        b[0] = mm_xor6(
            x[0],
            b[0],
            mm_rotl_epi32!(b[0], 2),
            mm_rotl_epi32!(b[0], 10),
            mm_rotl_epi32!(b[0], 18),
            mm_rotl_epi32!(b[0], 24),
        );

        x[0] = x[1];
        x[1] = x[2];
        x[2] = x[3];
        x[3] = b[0];
    }

    x[0] = _mm_shuffle_epi8(x[0], vindex);
    x[1] = _mm_shuffle_epi8(x[1], vindex);
    x[2] = _mm_shuffle_epi8(x[2], vindex);
    x[3] = _mm_shuffle_epi8(x[3], vindex);

    let out_block_ptr: *mut __m128i = out_ptr as *mut _;
    _mm_storeu_si128(out_block_ptr.add(0), mm_pack0_epi32(x[3], x[2], x[1], x[0]));
    _mm_storeu_si128(out_block_ptr.add(1), mm_pack1_epi32(x[3], x[2], x[1], x[0]));
    _mm_storeu_si128(out_block_ptr.add(2), mm_pack2_epi32(x[3], x[2], x[1], x[0]));
    _mm_storeu_si128(out_block_ptr.add(3), mm_pack3_epi32(x[3], x[2], x[1], x[0]));
}

#[inline]
pub fn sm4_encrypt4<T: ParBlocksSizeUser>(blocks: InOut<'_, '_, ParBlocks<T>>, rk: &[u32; 32]) {
    unsafe { sm4_process4::<T>(blocks, rk, true) }
}

#[inline]
pub fn sm4_decrypt4<T: ParBlocksSizeUser>(blocks: InOut<'_, '_, ParBlocks<T>>, rk: &[u32; 32]) {
    unsafe { sm4_process4::<T>(blocks, rk, false) }
}

/// SM4 block cipher.
#[derive(Clone)]
pub struct Sm4 {
    rk: [u32; 32],
}

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

impl BlockCipherEncrypt for Sm4 {
    #[inline]
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
        f.call(&Sm4Enc(self))
    }
}

pub struct Sm4Enc<'a>(&'a Sm4);

impl BlockSizeUser for Sm4Enc<'_> {
    type BlockSize = U16;
}

impl ParBlocksSizeUser for Sm4Enc<'_> {
    type ParBlocksSize = U4;
}

impl BlockCipherEncBackend for Sm4Enc<'_> {
    #[inline(always)]
    fn encrypt_block(&self, block: InOut<'_, '_, Block<Self>>) {
        crate::soft::sm4_encrypt::<Self>(block, &self.0.rk);
    }

    #[inline(always)]
    fn encrypt_par_blocks(&self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
        sm4_encrypt4::<Self>(blocks, &self.0.rk);
    }
}

impl BlockCipherDecrypt for Sm4 {
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
        f.call(&Sm4Dec(self))
    }
}

pub struct Sm4Dec<'a>(&'a Sm4);

impl BlockSizeUser for Sm4Dec<'_> {
    type BlockSize = U16;
}

impl ParBlocksSizeUser for Sm4Dec<'_> {
    type ParBlocksSize = U4;
}

impl BlockCipherDecBackend for Sm4Dec<'_> {
    #[inline(always)]
    fn decrypt_block(&self, block: InOut<'_, '_, Block<Self>>) {
        crate::soft::sm4_decrypt::<Self>(block, &self.0.rk);
    }

    #[inline(always)]
    fn decrypt_par_blocks(&self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
        sm4_decrypt4::<Self>(blocks, &self.0.rk);
    }
}
