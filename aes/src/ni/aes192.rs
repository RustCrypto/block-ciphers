use super::{
    arch::*,
    utils::{
        aesdec8, aesdeclast8, aesenc8, aesenclast8, load8, store8, xor8,
    },
};
use cipher::{
    consts::{U16, U24, U8},
    generic_array::GenericArray,
    BlockCipher, BlockProcessing, BlockDecrypt, BlockEncrypt, KeyInit, InOutVal, InOutBuf, InResOutBuf,
};
use crate::{Block, Block8};

mod expand;
#[cfg(test)]
mod test_expand;

/// AES-192 round keys
type RoundKeys = [__m128i; 13];

/// AES-192 block cipher
#[derive(Clone)]
pub struct Aes192 {
    encrypt_keys: RoundKeys,
    decrypt_keys: RoundKeys,
}

impl KeyInit for Aes192 {
    type KeySize = U24;

    #[inline]
    fn new(key: &GenericArray<u8, U24>) -> Self {
        let key = unsafe { &*(key as *const _ as *const [u8; 24]) };
        let (encrypt_keys, decrypt_keys) = expand::expand(key);
        Self {
            encrypt_keys,
            decrypt_keys,
        }
    }
}

impl BlockProcessing for Aes192 {
    type BlockSize = U16;
}

impl BlockCipher for Aes192 {}

impl BlockEncrypt for Aes192 {
    fn encrypt_block(&self, mut block: impl InOutVal<Block>) {
        let in_ptr = block.get_in() as *const Block;
        let out_ptr = block.get_out() as *mut Block;
        unsafe {
            aes192_encrypt1(&self.encrypt_keys, in_ptr, out_ptr);
        }
    }

    fn encrypt_blocks(
        &self,
        mut blocks: InOutBuf<'_, '_, Block>,
        proc: impl FnMut(InResOutBuf<'_, '_, '_, Block>),
    ) {
        blocks.chunks::<U8, _, _, _, _>(
            &self.encrypt_keys,
            |keys, inc, res| unsafe {
                aes192_encrypt8(
                    keys,
                    inc as *const Block8,
                    res as *mut Block8,
                )
            },
            |keys, inc, res| unsafe {
                let n = inc.len();
                res[..n].copy_from_slice(inc);
                aes192_encrypt8(
                    keys,
                    res as *const Block8,
                    res as *mut Block8,
                )
            },
            proc,
        );
    }
}

impl BlockDecrypt for Aes192 {
    fn decrypt_block(&self, mut block: impl InOutVal<Block>) {
        let in_ptr = block.get_in() as *const Block;
        let out_ptr = block.get_out() as *mut Block;
        unsafe {
            aes192_decrypt1(&self.decrypt_keys, in_ptr, out_ptr);
        }
    }

    fn decrypt_blocks(
        &self,
        mut blocks: InOutBuf<'_, '_, Block>,
        proc: impl FnMut(InResOutBuf<'_, '_, '_, Block>),
    ) {
        blocks.chunks::<U8, _, _, _, _>(
            &self.decrypt_keys,
            |keys, inc, res| unsafe {
                aes192_decrypt8(
                    keys,
                    inc as *const Block8,
                    res as *mut Block8,
                )
            },
            |keys, inc, res| unsafe {
                let n = inc.len();
                res[..n].copy_from_slice(inc);
                aes192_decrypt8(
                    keys,
                    res as *const Block8,
                    res as *mut Block8,
                )
            },
            proc,
        );
    }
}

opaque_debug::implement!(Aes192);

#[inline]
#[target_feature(enable = "aes")]
pub(crate) unsafe fn aes192_encrypt1(keys: &RoundKeys, in_ptr: *const Block, out_ptr: *mut Block) {
    // Safety: `loadu` and `storeu` support unaligned access
    #[allow(clippy::cast_ptr_alignment)]
    let mut block = _mm_loadu_si128(in_ptr as *const __m128i);
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
    block = _mm_aesenclast_si128(block, keys[12]);
    _mm_storeu_si128(out_ptr as *mut __m128i, block);
}

#[inline]
#[target_feature(enable = "aes")]
pub(crate) unsafe fn aes192_encrypt8(keys: &RoundKeys, in_ptr: *const Block8, out_ptr: *mut Block8) {
    let mut blocks = load8(in_ptr);
    xor8(&mut blocks, keys[0]);
    aesenc8(&mut blocks, keys[1]);
    aesenc8(&mut blocks, keys[2]);
    aesenc8(&mut blocks, keys[3]);
    aesenc8(&mut blocks, keys[4]);
    aesenc8(&mut blocks, keys[5]);
    aesenc8(&mut blocks, keys[6]);
    aesenc8(&mut blocks, keys[7]);
    aesenc8(&mut blocks, keys[8]);
    aesenc8(&mut blocks, keys[9]);
    aesenc8(&mut blocks, keys[10]);
    aesenc8(&mut blocks, keys[11]);
    aesenclast8(&mut blocks, keys[12]);
    store8(out_ptr, blocks);
}

#[inline]
#[target_feature(enable = "aes")]
unsafe fn aes192_decrypt1(keys: &RoundKeys, in_ptr: *const Block, out_ptr: *mut Block) {
    // Safety: `loadu` and `storeu` support unaligned access
    #[allow(clippy::cast_ptr_alignment)]
    let mut block = _mm_loadu_si128(in_ptr as *const __m128i);
    block = _mm_xor_si128(block, keys[12]);
    block = _mm_aesdec_si128(block, keys[11]);
    block = _mm_aesdec_si128(block, keys[10]);
    block = _mm_aesdec_si128(block, keys[9]);
    block = _mm_aesdec_si128(block, keys[8]);
    block = _mm_aesdec_si128(block, keys[7]);
    block = _mm_aesdec_si128(block, keys[6]);
    block = _mm_aesdec_si128(block, keys[5]);
    block = _mm_aesdec_si128(block, keys[4]);
    block = _mm_aesdec_si128(block, keys[3]);
    block = _mm_aesdec_si128(block, keys[2]);
    block = _mm_aesdec_si128(block, keys[1]);
    block = _mm_aesdeclast_si128(block, keys[0]);
    _mm_storeu_si128(out_ptr as *mut __m128i, block);
}

#[inline]
#[target_feature(enable = "aes")]
pub(crate) unsafe fn aes192_decrypt8(keys: &RoundKeys, in_ptr: *const Block8, out_ptr: *mut Block8) {
    let mut blocks = load8(in_ptr);
    xor8(&mut blocks, keys[12]);
    aesdec8(&mut blocks, keys[11]);
    aesdec8(&mut blocks, keys[10]);
    aesdec8(&mut blocks, keys[9]);
    aesdec8(&mut blocks, keys[8]);
    aesdec8(&mut blocks, keys[7]);
    aesdec8(&mut blocks, keys[6]);
    aesdec8(&mut blocks, keys[5]);
    aesdec8(&mut blocks, keys[4]);
    aesdec8(&mut blocks, keys[3]);
    aesdec8(&mut blocks, keys[2]);
    aesdec8(&mut blocks, keys[1]);
    aesdeclast8(&mut blocks, keys[0]);
    store8(out_ptr, blocks);
}
