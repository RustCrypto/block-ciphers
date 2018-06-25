use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::generic_array::typenum::{U16, U24, U8};
use block_cipher_trait::BlockCipher;
use core::arch::x86_64::*;

use core::{fmt, mem};
use utils::{Block128, Block128x8};

mod expand;
#[cfg(test)]
mod test_expand;

/// AES-192 block cipher
#[derive(Copy, Clone)]
pub struct Aes192 {
    encrypt_keys: [__m128i; 13],
    decrypt_keys: [__m128i; 13],
}

impl Aes192 {
    #[inline(always)]
    pub(crate) fn encrypt8(&self, blocks: [__m128i; 8]) -> [__m128i; 8] {
        let keys = self.encrypt_keys;
        unsafe {
            let mut b = (
                blocks[0], blocks[1], blocks[2], blocks[3],
                blocks[4], blocks[5], blocks[6], blocks[7],
            );
            xor8!(b, keys[0]);
            aesenc8!(b, keys[1]);
            aesenc8!(b, keys[2]);
            aesenc8!(b, keys[3]);
            aesenc8!(b, keys[4]);
            aesenc8!(b, keys[5]);
            aesenc8!(b, keys[6]);
            aesenc8!(b, keys[7]);
            aesenc8!(b, keys[8]);
            aesenc8!(b, keys[9]);
            aesenc8!(b, keys[10]);
            aesenc8!(b, keys[11]);
            aesenclast8!(b, keys[12]);

            [b.0, b.1, b.2, b.3, b.4, b.5, b.6, b.7]
        }
    }

    #[inline(always)]
    pub(crate) fn encrypt(&self, mut block: __m128i) -> __m128i {
        let keys = self.encrypt_keys;
        unsafe {
            block = _mm_xor_si128(block, keys[0]);
            block = _mm_aesenc_si128(block, keys[1]);
            block = _mm_aesenc_si128(block, keys[2]);
            block = _mm_aesenc_si128(block, keys[3]);
            block = _mm_aesenc_si128(block, keys[4]);
            block = _mm_aesenc_si128(block, keys[5]);
            block = _mm_aesenc_si128(block, keys[6]);
            block = _mm_aesenc_si128(block, keys[7]);
            block = _mm_aesenc_si128(block, keys[8]);
            block = _mm_aesenc_si128(block, keys[9]);
            block = _mm_aesenc_si128(block, keys[10]);
            block = _mm_aesenc_si128(block, keys[11]);
            _mm_aesenclast_si128(block, keys[12])
        }
    }
}

impl BlockCipher for Aes192 {
    type KeySize = U24;
    type BlockSize = U16;
    type ParBlocks = U8;

    #[inline]
    fn new(key: &GenericArray<u8, U24>) -> Self {
        let key = unsafe { mem::transmute(key) };
        let (encrypt_keys, decrypt_keys) = expand::expand(key);
        Self {
            encrypt_keys,
            decrypt_keys,
        }
    }

    #[inline]
    fn encrypt_block(&self, block: &mut Block128) {
        unsafe {
            let b = _mm_loadu_si128(block.as_ptr() as *const __m128i);
            let b = self.encrypt(b);
            _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, b);
        }
    }

    #[inline]
    fn decrypt_block(&self, block: &mut Block128) {
        let keys = self.decrypt_keys;
        unsafe {
            let mut b = _mm_loadu_si128(block.as_ptr() as *const __m128i);
            b = _mm_xor_si128(b, keys[12]);
            b = _mm_aesdec_si128(b, keys[11]);
            b = _mm_aesdec_si128(b, keys[10]);
            b = _mm_aesdec_si128(b, keys[9]);
            b = _mm_aesdec_si128(b, keys[8]);
            b = _mm_aesdec_si128(b, keys[7]);
            b = _mm_aesdec_si128(b, keys[6]);
            b = _mm_aesdec_si128(b, keys[5]);
            b = _mm_aesdec_si128(b, keys[4]);
            b = _mm_aesdec_si128(b, keys[3]);
            b = _mm_aesdec_si128(b, keys[2]);
            b = _mm_aesdec_si128(b, keys[1]);
            b = _mm_aesdeclast_si128(b, keys[0]);
            _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, b);
        }
    }

    #[inline]
    fn encrypt_blocks(&self, blocks: &mut Block128x8) {
        let keys = self.encrypt_keys;
        unsafe {
            let mut b = load8!(blocks);
            xor8!(b, keys[0]);
            aesenc8!(b, keys[1]);
            aesenc8!(b, keys[2]);
            aesenc8!(b, keys[3]);
            aesenc8!(b, keys[4]);
            aesenc8!(b, keys[5]);
            aesenc8!(b, keys[6]);
            aesenc8!(b, keys[7]);
            aesenc8!(b, keys[8]);
            aesenc8!(b, keys[9]);
            aesenc8!(b, keys[10]);
            aesenc8!(b, keys[11]);
            aesenclast8!(b, keys[12]);
            store8!(blocks, b);
        }
    }

    #[inline]
    fn decrypt_blocks(&self, blocks: &mut Block128x8) {
        let keys = self.decrypt_keys;
        unsafe {
            let mut b = load8!(blocks);
            xor8!(b, keys[12]);
            aesdec8!(b, keys[11]);
            aesdec8!(b, keys[10]);
            aesdec8!(b, keys[9]);
            aesdec8!(b, keys[8]);
            aesdec8!(b, keys[7]);
            aesdec8!(b, keys[6]);
            aesdec8!(b, keys[5]);
            aesdec8!(b, keys[4]);
            aesdec8!(b, keys[3]);
            aesdec8!(b, keys[2]);
            aesdec8!(b, keys[1]);
            aesdeclast8!(b, keys[0]);
            store8!(blocks, b);
        }
    }
}

impl_opaque_debug!(Aes192);
