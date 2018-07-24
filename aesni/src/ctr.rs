use core::{mem, fmt};
use arch::*;

use super::{Aes128, Aes192, Aes256, BlockCipher};
use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::generic_array::typenum::{U16, U24, U32};
use stream_cipher::{
    StreamCipherCore, StreamCipherSeek, NewFixStreamCipher, LoopError,
};

const BLOCK_SIZE: usize = 16;
const PAR_BLOCKS: usize = 8;
const PAR_BLOCKS_SIZE: usize = PAR_BLOCKS*BLOCK_SIZE;

#[inline(always)]
fn xor_block8(buf: &mut [u8], ctr: [__m128i; 8]) {
    debug_assert_eq!(buf.len(), PAR_BLOCKS_SIZE);
    unsafe {
        // compiler should unroll this loop
        for i in 0..8 {
            let ptr = buf.as_mut_ptr().offset(16*i) as *mut __m128i;
            let data = _mm_loadu_si128(ptr);
            let data = _mm_xor_si128(data, ctr[i as usize]);
            _mm_storeu_si128(ptr, data);
        }
    }
}

#[inline(always)]
fn swap_bytes(v: __m128i) -> __m128i {
    unsafe {
        let mask = _mm_set_epi64x(0x08090a0b0c0d0e0f, 0x0001020304050607);
        _mm_shuffle_epi8(v, mask)
    }
}

#[inline(always)]
fn inc_be(v: __m128i) -> __m128i {
    unsafe { _mm_add_epi64(v, _mm_set_epi64x(1, 0)) }
}

#[inline(always)]
fn load(val: &GenericArray<u8, U16>) -> __m128i {
    unsafe { _mm_loadu_si128(val.as_ptr() as *const __m128i) }
}


macro_rules! impl_ctr {
    ($name:ident, $cipher:ty, $key_size:ty, $doc:expr) => {
        #[doc=$doc]
        #[derive(Clone)]
        pub struct $name {
            nonce: __m128i,
            ctr: __m128i,
            cipher: $cipher,

            leftover_buf: [u8; BLOCK_SIZE],
            leftover_cursor: Option<u8>,
        }

        impl $name {
            #[inline(always)]
            fn next_block(&mut self) -> __m128i {
                let block = swap_bytes(self.ctr);
                self.ctr = inc_be(self.ctr);
                self.cipher.encrypt(block)
            }

            #[inline(always)]
            fn next_block8(&mut self) -> [__m128i; 8] {
                let mut ctr = self.ctr;
                let block8 = [
                    swap_bytes(ctr),
                    { ctr = inc_be(ctr); swap_bytes(ctr) },
                    { ctr = inc_be(ctr); swap_bytes(ctr) },
                    { ctr = inc_be(ctr); swap_bytes(ctr) },
                    { ctr = inc_be(ctr); swap_bytes(ctr) },
                    { ctr = inc_be(ctr); swap_bytes(ctr) },
                    { ctr = inc_be(ctr); swap_bytes(ctr) },
                    { ctr = inc_be(ctr); swap_bytes(ctr) },
                ];
                self.ctr = inc_be(ctr);

                self.cipher.encrypt8(block8)
            }

            #[inline(always)]
            fn get_u64_ctr(&self) -> u64 {
                let ctr: [u64; 2] = unsafe { mem::transmute(self.ctr) };
                let nonce: [u64; 2] = unsafe { mem::transmute(self.nonce) };
                ctr[1].wrapping_sub(nonce[1])
            }
        }

        impl NewFixStreamCipher for $name {
            type KeySize = $key_size;
            type NonceSize = U16;
            fn new(
                key: &GenericArray<u8, $key_size>, nonce: &GenericArray<u8, U16>,
            ) -> Self {
                let nonce = swap_bytes(load(nonce));
                let cipher = <$cipher>::new(key);
                Self {
                    nonce,
                    ctr: nonce,
                    cipher,
                    leftover_cursor: None,
                    leftover_buf: [0u8; BLOCK_SIZE],
                }
            }
        }

        impl StreamCipherCore for $name {
            #[inline]
            fn try_apply_keystream(&mut self, mut data: &mut [u8])
                -> Result<(), LoopError>
            {
                // process leftover bytes from the last call if any
                if let Some(pos) = self.leftover_cursor {
                    let pos = pos as usize;
                    // check if input buffer is large enough to be xor'ed
                    // with all leftover bytes
                    if data.len() >= BLOCK_SIZE - pos {
                        let buf = &self.leftover_buf[pos..];
                        let (r, l) = {data}.split_at_mut(buf.len());
                        data = l;
                        for (a, b) in r.iter_mut().zip(buf) { *a ^= *b; }
                    } else {
                        let buf = &self.leftover_buf[pos..pos + data.len()];
                        self.leftover_cursor = Some((pos + data.len()) as u8);

                        for (a, b) in data.iter_mut().zip(buf) { *a ^= *b; }
                        return Ok(());
                    }
                }
                self.leftover_cursor = None;

                // check if counter will loop for given data length
                let data_blocks = data.len() / BLOCK_SIZE;
                let counter = self.get_u64_ctr();
                if counter.checked_add(data_blocks as u64).is_none() {
                    return Err(LoopError);
                }

                // process 8 blocks at a time
                while data.len() >= PAR_BLOCKS_SIZE {
                    let (r, l) = {data}.split_at_mut(PAR_BLOCKS_SIZE);
                    data = l;
                    xor_block8(r, self.next_block8());
                }

                // process one block at a time
                while data.len() >= BLOCK_SIZE {
                    let (r, l) = {data}.split_at_mut(BLOCK_SIZE);
                    data = l;

                    let block = self.next_block();

                    unsafe {
                        let t = _mm_loadu_si128(r.as_ptr() as *const __m128i);
                        let res = _mm_xor_si128(block, t);
                        _mm_storeu_si128(r.as_mut_ptr() as *mut __m128i, res);
                    }
                }

                // process leftover bytes
                if data.len() != 0 {
                    let block = self.next_block();
                    self.leftover_buf = unsafe {
                         mem::transmute::<__m128i, [u8; BLOCK_SIZE]>(block)
                    };
                    let n = data.len();
                    self.leftover_cursor = Some(n as u8);
                    for (a, b) in data.iter_mut().zip(&self.leftover_buf[..n]) {
                        *a ^= *b;
                    }
                }
                Ok(())
            }
        }

        impl StreamCipherSeek for $name {
            fn current_pos(&self) -> u64 {
                self.get_u64_ctr()
            }

            // TODO: check correctness
            fn seek(&mut self, pos: u64) {
                let n = pos / BLOCK_SIZE as u64;
                let l = pos % BLOCK_SIZE as u64;
                self.ctr = unsafe {
                    _mm_add_epi64(self.nonce, _mm_set_epi64x(n as i64, 0))
                };
                if l == 0 {
                    self.leftover_cursor = None;
                } else {
                    self.leftover_buf = unsafe {
                        mem::transmute(self.next_block())
                    };
                    self.leftover_cursor = Some(l as u8);
                }
            }
        }

        impl_opaque_debug!($name);
    }
}

impl_ctr!(Aes128Ctr, Aes128, U16, "AES128 in CTR mode");
impl_ctr!(Aes192Ctr, Aes192, U24, "AES192 in CTR mode");
impl_ctr!(Aes256Ctr, Aes256, U32, "AES256 in CTR mode");
