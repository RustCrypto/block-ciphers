use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::generic_array::typenum::{U16, U8};
use block_cipher_trait::BlockCipher;
use core::arch::x86_64::*;

use core::{fmt, mem};
use utils::{Block128, Block128x8};

mod expand;
#[cfg(test)]
mod test_expand;

/// AES-128 block cipher
#[derive(Copy, Clone)]
pub struct Aes128 {
    encrypt_keys: [__m128i; 11],
    decrypt_keys: [__m128i; 11],
}

impl BlockCipher for Aes128 {
    type KeySize = U16;
    type BlockSize = U16;
    type ParBlocks = U8;

    #[inline]
    fn new(key: &GenericArray<u8, U16>) -> Self {
        let key = unsafe { mem::transmute(key) };
        let (encrypt_keys, decrypt_keys) = expand::expand(key);
        Self {
            encrypt_keys,
            decrypt_keys,
        }
    }

    #[inline]
    fn encrypt_block(&self, block: &mut Block128) {
        let keys = self.encrypt_keys;
        unsafe {
            let mut b = _mm_loadu_si128(block.as_ptr() as *const __m128i);
            b = _mm_xor_si128(b, keys[0]);
            b = _mm_aesenc_si128(b, keys[1]);
            b = _mm_aesenc_si128(b, keys[2]);
            b = _mm_aesenc_si128(b, keys[3]);
            b = _mm_aesenc_si128(b, keys[4]);
            b = _mm_aesenc_si128(b, keys[5]);
            b = _mm_aesenc_si128(b, keys[6]);
            b = _mm_aesenc_si128(b, keys[7]);
            b = _mm_aesenc_si128(b, keys[8]);
            b = _mm_aesenc_si128(b, keys[9]);
            b = _mm_aesenclast_si128(b, keys[10]);
            _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, b);
        }
    }

    #[inline]
    fn decrypt_block(&self, block: &mut Block128) {
        let keys = self.decrypt_keys;
        unsafe {
            let mut b = _mm_loadu_si128(block.as_ptr() as *const __m128i);
            b = _mm_xor_si128(b, keys[10]);
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
            let mut b0 = _mm_loadu_si128(blocks[0].as_ptr() as *const __m128i);
            let mut b1 = _mm_loadu_si128(blocks[1].as_ptr() as *const __m128i);
            let mut b2 = _mm_loadu_si128(blocks[2].as_ptr() as *const __m128i);
            let mut b3 = _mm_loadu_si128(blocks[3].as_ptr() as *const __m128i);
            let mut b4 = _mm_loadu_si128(blocks[4].as_ptr() as *const __m128i);
            let mut b5 = _mm_loadu_si128(blocks[5].as_ptr() as *const __m128i);
            let mut b6 = _mm_loadu_si128(blocks[6].as_ptr() as *const __m128i);
            let mut b7 = _mm_loadu_si128(blocks[7].as_ptr() as *const __m128i);

            b0 = _mm_xor_si128(b0, keys[0]);
            b1 = _mm_xor_si128(b1, keys[0]);
            b2 = _mm_xor_si128(b2, keys[0]);
            b3 = _mm_xor_si128(b3, keys[0]);
            b4 = _mm_xor_si128(b4, keys[0]);
            b5 = _mm_xor_si128(b5, keys[0]);
            b6 = _mm_xor_si128(b6, keys[0]);
            b7 = _mm_xor_si128(b7, keys[0]);

            b0 = _mm_aesenc_si128(b0, keys[1]);
            b1 = _mm_aesenc_si128(b1, keys[1]);
            b2 = _mm_aesenc_si128(b2, keys[1]);
            b3 = _mm_aesenc_si128(b3, keys[1]);
            b4 = _mm_aesenc_si128(b4, keys[1]);
            b5 = _mm_aesenc_si128(b5, keys[1]);
            b6 = _mm_aesenc_si128(b6, keys[1]);
            b7 = _mm_aesenc_si128(b7, keys[1]);

            b0 = _mm_aesenc_si128(b0, keys[2]);
            b1 = _mm_aesenc_si128(b1, keys[2]);
            b2 = _mm_aesenc_si128(b2, keys[2]);
            b3 = _mm_aesenc_si128(b3, keys[2]);
            b4 = _mm_aesenc_si128(b4, keys[2]);
            b5 = _mm_aesenc_si128(b5, keys[2]);
            b6 = _mm_aesenc_si128(b6, keys[2]);
            b7 = _mm_aesenc_si128(b7, keys[2]);

            b0 = _mm_aesenc_si128(b0, keys[3]);
            b1 = _mm_aesenc_si128(b1, keys[3]);
            b2 = _mm_aesenc_si128(b2, keys[3]);
            b3 = _mm_aesenc_si128(b3, keys[3]);
            b4 = _mm_aesenc_si128(b4, keys[3]);
            b5 = _mm_aesenc_si128(b5, keys[3]);
            b6 = _mm_aesenc_si128(b6, keys[3]);
            b7 = _mm_aesenc_si128(b7, keys[3]);

            b0 = _mm_aesenc_si128(b0, keys[4]);
            b1 = _mm_aesenc_si128(b1, keys[4]);
            b2 = _mm_aesenc_si128(b2, keys[4]);
            b3 = _mm_aesenc_si128(b3, keys[4]);
            b4 = _mm_aesenc_si128(b4, keys[4]);
            b5 = _mm_aesenc_si128(b5, keys[4]);
            b6 = _mm_aesenc_si128(b6, keys[4]);
            b7 = _mm_aesenc_si128(b7, keys[4]);

            b0 = _mm_aesenc_si128(b0, keys[5]);
            b1 = _mm_aesenc_si128(b1, keys[5]);
            b2 = _mm_aesenc_si128(b2, keys[5]);
            b3 = _mm_aesenc_si128(b3, keys[5]);
            b4 = _mm_aesenc_si128(b4, keys[5]);
            b5 = _mm_aesenc_si128(b5, keys[5]);
            b6 = _mm_aesenc_si128(b6, keys[5]);
            b7 = _mm_aesenc_si128(b7, keys[5]);

            b0 = _mm_aesenc_si128(b0, keys[6]);
            b1 = _mm_aesenc_si128(b1, keys[6]);
            b2 = _mm_aesenc_si128(b2, keys[6]);
            b3 = _mm_aesenc_si128(b3, keys[6]);
            b4 = _mm_aesenc_si128(b4, keys[6]);
            b5 = _mm_aesenc_si128(b5, keys[6]);
            b6 = _mm_aesenc_si128(b6, keys[6]);
            b7 = _mm_aesenc_si128(b7, keys[6]);

            b0 = _mm_aesenc_si128(b0, keys[7]);
            b1 = _mm_aesenc_si128(b1, keys[7]);
            b2 = _mm_aesenc_si128(b2, keys[7]);
            b3 = _mm_aesenc_si128(b3, keys[7]);
            b4 = _mm_aesenc_si128(b4, keys[7]);
            b5 = _mm_aesenc_si128(b5, keys[7]);
            b6 = _mm_aesenc_si128(b6, keys[7]);
            b7 = _mm_aesenc_si128(b7, keys[7]);

            b0 = _mm_aesenc_si128(b0, keys[8]);
            b1 = _mm_aesenc_si128(b1, keys[8]);
            b2 = _mm_aesenc_si128(b2, keys[8]);
            b3 = _mm_aesenc_si128(b3, keys[8]);
            b4 = _mm_aesenc_si128(b4, keys[8]);
            b5 = _mm_aesenc_si128(b5, keys[8]);
            b6 = _mm_aesenc_si128(b6, keys[8]);
            b7 = _mm_aesenc_si128(b7, keys[8]);

            b0 = _mm_aesenc_si128(b0, keys[9]);
            b1 = _mm_aesenc_si128(b1, keys[9]);
            b2 = _mm_aesenc_si128(b2, keys[9]);
            b3 = _mm_aesenc_si128(b3, keys[9]);
            b4 = _mm_aesenc_si128(b4, keys[9]);
            b5 = _mm_aesenc_si128(b5, keys[9]);
            b6 = _mm_aesenc_si128(b6, keys[9]);
            b7 = _mm_aesenc_si128(b7, keys[9]);

            b0 = _mm_aesenclast_si128(b0, keys[10]);
            b1 = _mm_aesenclast_si128(b1, keys[10]);
            b2 = _mm_aesenclast_si128(b2, keys[10]);
            b3 = _mm_aesenclast_si128(b3, keys[10]);
            b4 = _mm_aesenclast_si128(b4, keys[10]);
            b5 = _mm_aesenclast_si128(b5, keys[10]);
            b6 = _mm_aesenclast_si128(b6, keys[10]);
            b7 = _mm_aesenclast_si128(b7, keys[10]);

            _mm_storeu_si128(blocks[0].as_mut_ptr() as *mut __m128i, b0);
            _mm_storeu_si128(blocks[1].as_mut_ptr() as *mut __m128i, b1);
            _mm_storeu_si128(blocks[2].as_mut_ptr() as *mut __m128i, b2);
            _mm_storeu_si128(blocks[3].as_mut_ptr() as *mut __m128i, b3);
            _mm_storeu_si128(blocks[4].as_mut_ptr() as *mut __m128i, b4);
            _mm_storeu_si128(blocks[5].as_mut_ptr() as *mut __m128i, b5);
            _mm_storeu_si128(blocks[6].as_mut_ptr() as *mut __m128i, b6);
            _mm_storeu_si128(blocks[7].as_mut_ptr() as *mut __m128i, b7);
        }
    }

    #[inline]
    fn decrypt_blocks(&self, blocks: &mut Block128x8) {
        let keys = self.decrypt_keys;
        unsafe {
            let mut b0 = _mm_loadu_si128(blocks[0].as_ptr() as *const __m128i);
            let mut b1 = _mm_loadu_si128(blocks[1].as_ptr() as *const __m128i);
            let mut b2 = _mm_loadu_si128(blocks[2].as_ptr() as *const __m128i);
            let mut b3 = _mm_loadu_si128(blocks[3].as_ptr() as *const __m128i);
            let mut b4 = _mm_loadu_si128(blocks[4].as_ptr() as *const __m128i);
            let mut b5 = _mm_loadu_si128(blocks[5].as_ptr() as *const __m128i);
            let mut b6 = _mm_loadu_si128(blocks[6].as_ptr() as *const __m128i);
            let mut b7 = _mm_loadu_si128(blocks[7].as_ptr() as *const __m128i);

            b0 = _mm_xor_si128(b0, keys[10]);
            b1 = _mm_xor_si128(b1, keys[10]);
            b2 = _mm_xor_si128(b2, keys[10]);
            b3 = _mm_xor_si128(b3, keys[10]);
            b4 = _mm_xor_si128(b4, keys[10]);
            b5 = _mm_xor_si128(b5, keys[10]);
            b6 = _mm_xor_si128(b6, keys[10]);
            b7 = _mm_xor_si128(b7, keys[10]);

            b0 = _mm_aesdec_si128(b0, keys[9]);
            b1 = _mm_aesdec_si128(b1, keys[9]);
            b2 = _mm_aesdec_si128(b2, keys[9]);
            b3 = _mm_aesdec_si128(b3, keys[9]);
            b4 = _mm_aesdec_si128(b4, keys[9]);
            b5 = _mm_aesdec_si128(b5, keys[9]);
            b6 = _mm_aesdec_si128(b6, keys[9]);
            b7 = _mm_aesdec_si128(b7, keys[9]);

            b0 = _mm_aesdec_si128(b0, keys[8]);
            b1 = _mm_aesdec_si128(b1, keys[8]);
            b2 = _mm_aesdec_si128(b2, keys[8]);
            b3 = _mm_aesdec_si128(b3, keys[8]);
            b4 = _mm_aesdec_si128(b4, keys[8]);
            b5 = _mm_aesdec_si128(b5, keys[8]);
            b6 = _mm_aesdec_si128(b6, keys[8]);
            b7 = _mm_aesdec_si128(b7, keys[8]);

            b0 = _mm_aesdec_si128(b0, keys[7]);
            b1 = _mm_aesdec_si128(b1, keys[7]);
            b2 = _mm_aesdec_si128(b2, keys[7]);
            b3 = _mm_aesdec_si128(b3, keys[7]);
            b4 = _mm_aesdec_si128(b4, keys[7]);
            b5 = _mm_aesdec_si128(b5, keys[7]);
            b6 = _mm_aesdec_si128(b6, keys[7]);
            b7 = _mm_aesdec_si128(b7, keys[7]);

            b0 = _mm_aesdec_si128(b0, keys[6]);
            b1 = _mm_aesdec_si128(b1, keys[6]);
            b2 = _mm_aesdec_si128(b2, keys[6]);
            b3 = _mm_aesdec_si128(b3, keys[6]);
            b4 = _mm_aesdec_si128(b4, keys[6]);
            b5 = _mm_aesdec_si128(b5, keys[6]);
            b6 = _mm_aesdec_si128(b6, keys[6]);
            b7 = _mm_aesdec_si128(b7, keys[6]);

            b0 = _mm_aesdec_si128(b0, keys[5]);
            b1 = _mm_aesdec_si128(b1, keys[5]);
            b2 = _mm_aesdec_si128(b2, keys[5]);
            b3 = _mm_aesdec_si128(b3, keys[5]);
            b4 = _mm_aesdec_si128(b4, keys[5]);
            b5 = _mm_aesdec_si128(b5, keys[5]);
            b6 = _mm_aesdec_si128(b6, keys[5]);
            b7 = _mm_aesdec_si128(b7, keys[5]);

            b0 = _mm_aesdec_si128(b0, keys[4]);
            b1 = _mm_aesdec_si128(b1, keys[4]);
            b2 = _mm_aesdec_si128(b2, keys[4]);
            b3 = _mm_aesdec_si128(b3, keys[4]);
            b4 = _mm_aesdec_si128(b4, keys[4]);
            b5 = _mm_aesdec_si128(b5, keys[4]);
            b6 = _mm_aesdec_si128(b6, keys[4]);
            b7 = _mm_aesdec_si128(b7, keys[4]);

            b0 = _mm_aesdec_si128(b0, keys[3]);
            b1 = _mm_aesdec_si128(b1, keys[3]);
            b2 = _mm_aesdec_si128(b2, keys[3]);
            b3 = _mm_aesdec_si128(b3, keys[3]);
            b4 = _mm_aesdec_si128(b4, keys[3]);
            b5 = _mm_aesdec_si128(b5, keys[3]);
            b6 = _mm_aesdec_si128(b6, keys[3]);
            b7 = _mm_aesdec_si128(b7, keys[3]);

            b0 = _mm_aesdec_si128(b0, keys[2]);
            b1 = _mm_aesdec_si128(b1, keys[2]);
            b2 = _mm_aesdec_si128(b2, keys[2]);
            b3 = _mm_aesdec_si128(b3, keys[2]);
            b4 = _mm_aesdec_si128(b4, keys[2]);
            b5 = _mm_aesdec_si128(b5, keys[2]);
            b6 = _mm_aesdec_si128(b6, keys[2]);
            b7 = _mm_aesdec_si128(b7, keys[2]);

            b0 = _mm_aesdec_si128(b0, keys[1]);
            b1 = _mm_aesdec_si128(b1, keys[1]);
            b2 = _mm_aesdec_si128(b2, keys[1]);
            b3 = _mm_aesdec_si128(b3, keys[1]);
            b4 = _mm_aesdec_si128(b4, keys[1]);
            b5 = _mm_aesdec_si128(b5, keys[1]);
            b6 = _mm_aesdec_si128(b6, keys[1]);
            b7 = _mm_aesdec_si128(b7, keys[1]);

            b0 = _mm_aesdeclast_si128(b0, keys[0]);
            b1 = _mm_aesdeclast_si128(b1, keys[0]);
            b2 = _mm_aesdeclast_si128(b2, keys[0]);
            b3 = _mm_aesdeclast_si128(b3, keys[0]);
            b4 = _mm_aesdeclast_si128(b4, keys[0]);
            b5 = _mm_aesdeclast_si128(b5, keys[0]);
            b6 = _mm_aesdeclast_si128(b6, keys[0]);
            b7 = _mm_aesdeclast_si128(b7, keys[0]);

            _mm_storeu_si128(blocks[0].as_mut_ptr() as *mut __m128i, b0);
            _mm_storeu_si128(blocks[1].as_mut_ptr() as *mut __m128i, b1);
            _mm_storeu_si128(blocks[2].as_mut_ptr() as *mut __m128i, b2);
            _mm_storeu_si128(blocks[3].as_mut_ptr() as *mut __m128i, b3);
            _mm_storeu_si128(blocks[4].as_mut_ptr() as *mut __m128i, b4);
            _mm_storeu_si128(blocks[5].as_mut_ptr() as *mut __m128i, b5);
            _mm_storeu_si128(blocks[6].as_mut_ptr() as *mut __m128i, b6);
            _mm_storeu_si128(blocks[7].as_mut_ptr() as *mut __m128i, b7);
        }
    }
}

impl_opaque_debug!(Aes128);
