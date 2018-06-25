use core::{mem, fmt};


use core::arch::x86_64::*;
use super::{Aes128, Aes192, Aes256, BlockCipher};
use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::generic_array::typenum::{U16, U24, U32};

const BLOCK_SIZE: usize = 16;
const PAR_BLOCKS: usize = 8;
const PAR_BLOCKS_SIZE: usize = PAR_BLOCKS*BLOCK_SIZE;

#[inline(always)]
fn xor_block8(buf: &mut [u8], ctr: [__m128i; 8]) {
    debug_assert_eq!(buf.len(), PAR_BLOCKS_SIZE);
    unsafe {
        let t = &mut *(buf.as_mut_ptr() as *mut [__m128i; PAR_BLOCKS]);
        t[0] = _mm_xor_si128(t[0], ctr[0]);
        t[1] = _mm_xor_si128(t[1], ctr[1]);
        t[2] = _mm_xor_si128(t[2], ctr[2]);
        t[3] = _mm_xor_si128(t[3], ctr[3]);
        t[4] = _mm_xor_si128(t[4], ctr[4]);
        t[5] = _mm_xor_si128(t[5], ctr[5]);
        t[6] = _mm_xor_si128(t[6], ctr[6]);
        t[7] = _mm_xor_si128(t[7], ctr[7]);
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
fn load(val: &[u8; BLOCK_SIZE]) -> __m128i {
    unsafe { _mm_loadu_si128(val.as_ptr() as *const __m128i) }
}


macro_rules! impl_ctr {
    ($name:ident, $cipher:ty, $key_size:ty, $doc:expr) => {
        #[doc=$doc]
        #[derive(Clone)]
        pub struct $name {
            ctr: __m128i,
            cipher: $cipher,

            leftover_buf: [u8; BLOCK_SIZE],
            leftover_cursor: usize,
        }

        impl $name {
            pub fn new(
                key: &GenericArray<u8, $key_size>, nonce: &[u8; BLOCK_SIZE],
            ) -> Self {
                let ctr = swap_bytes(load(nonce));
                let cipher = <$cipher>::new(key);
                Self{
                    ctr, cipher,
                    leftover_cursor: BLOCK_SIZE,
                    leftover_buf: [0u8; BLOCK_SIZE]
                }
            }

            #[inline]
            pub fn xor(&mut self, mut buf: &mut [u8]) {
                // process leftover bytes from the last call if any
                if self.leftover_cursor != BLOCK_SIZE {
                    // check if input buffer is large enough to be xor'ed
                    // with all leftover bytes
                    if buf.len() >= BLOCK_SIZE - self.leftover_cursor {
                        let n = self.leftover_cursor;
                        let leftover = &self.leftover_buf[n..];
                        let (r, l) = {buf}.split_at_mut(leftover.len());
                        buf = l;
                        for (a, b) in r.iter_mut().zip(leftover) { *a ^= *b; }
                        self.leftover_cursor = BLOCK_SIZE;
                    } else {
                        let s = self.leftover_cursor;
                        let leftover = &self.leftover_buf[s..s + buf.len()];
                        self.leftover_cursor += buf.len();

                        for (a, b) in buf.iter_mut().zip(leftover) { *a ^= *b; }
                        return;
                    }
                }

                // process 8 blocks at a time
                while buf.len() >= PAR_BLOCKS_SIZE {
                    let (r, l) = {buf}.split_at_mut(PAR_BLOCKS_SIZE);
                    buf = l;
                    xor_block8(r, self.next_block8());
                }

                // process one block at a time
                while buf.len() >= BLOCK_SIZE {
                    let (r, l) = {buf}.split_at_mut(BLOCK_SIZE);
                    buf = l;

                    let block = self.next_block();

                    unsafe {
                        let t = _mm_loadu_si128(r.as_ptr() as *const __m128i);
                        let res = _mm_xor_si128(block, t);
                        _mm_storeu_si128(r.as_mut_ptr() as *mut __m128i, res);
                    }
                }

                // process leftover bytes
                if buf.len() != 0 {
                    let block = self.next_block();
                    self.leftover_buf = unsafe {
                         mem::transmute::<__m128i, [u8; BLOCK_SIZE]>(block)
                    };
                    let n = buf.len();
                    self.leftover_cursor = n;
                    for (a, b) in buf.iter_mut().zip(&self.leftover_buf[..n]) {
                        *a ^= *b;
                    }
                }
            }

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
        }

        impl_opaque_debug!($name);
    }
}

impl_ctr!(CtrAes128, Aes128, U16, "AES128 in CTR mode");
impl_ctr!(CtrAes192, Aes192, U24, "AES192 in CTR mode");
impl_ctr!(CtrAes256, Aes256, U32, "AES256 in CTR mode");
