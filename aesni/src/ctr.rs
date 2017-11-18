use core::mem;

use u64x2::u64x2;
use super::{Aes128, Aes192, Aes256};

const BLOCK_SIZE: usize = 16;
const PAR_BLOCKS: usize = 8;
const PAR_BLOCKS_SIZE: usize = PAR_BLOCKS*BLOCK_SIZE;

#[inline(always)]
fn xor_block8(buf: &mut [u8], ctr: [u64x2; 8]) {
    assert_eq!(buf.len(), PAR_BLOCKS_SIZE);
    let t = unsafe {
        &mut *(buf.as_mut_ptr() as *mut [u64x2; PAR_BLOCKS])
    };
    for i in 0..PAR_BLOCKS {
        t[i].0 ^= ctr[i].0;
        t[i].1 ^= ctr[i].1;
    }
}

macro_rules! impl_ctr {
    ($name:ident, $cipher:ty, $key_size:expr, $doc:expr) => {
        #[doc=$doc]
        pub struct $name {
            ctr: u64x2,
            cipher: $cipher,

            leftover_buf: [u8; BLOCK_SIZE],
            leftover_cursor: usize,
        }

        impl $name {
            pub fn new(key: &[u8; $key_size], nonce: &[u8; BLOCK_SIZE]) -> Self {
                let ctr = u64x2::read(nonce).swap_bytes();
                let cipher = <$cipher>::init(key);
                Self{
                    ctr, cipher,
                    leftover_cursor: BLOCK_SIZE,
                    leftover_buf: [0u8; BLOCK_SIZE]
                }
            }

            pub fn new_from_cipher(cipher: $cipher, nonce: &[u8; BLOCK_SIZE]) -> Self {
                let ctr = u64x2::read(nonce).swap_bytes();
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
                        for (a, b) in r.iter_mut().zip(leftover) { *a ^= b; }
                        self.leftover_cursor = BLOCK_SIZE;
                    } else {
                        let s = self.leftover_cursor;
                        let leftover = &self.leftover_buf[s..s + buf.len()];
                        self.leftover_cursor += buf.len();

                        for (a, b) in buf.iter_mut().zip(leftover) { *a ^= b; }
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

                    let t = unsafe {
                        &mut *(r.as_mut_ptr() as *mut u64x2)
                    };
                    t.0 ^= block.0;
                    t.1 ^= block.1;
                }

                // process leftover bytes
                if buf.len() != 0 {
                    let block = self.next_block();
                    self.leftover_buf = unsafe {
                         mem::transmute::<u64x2, [u8; BLOCK_SIZE]>(block)
                    };
                    let n = buf.len();
                    self.leftover_cursor = n;
                    for (a, b) in buf.iter_mut().zip(&self.leftover_buf[..n]) {
                        *a ^= b;
                    }
                }
            }

            #[inline(always)]
            fn next_block(&mut self) -> u64x2 {
                let mut block = self.ctr.swap_bytes();
                self.ctr.inc_be();
                self.cipher.encrypt_u64x2(&mut block);
                block
            }

            #[inline(always)]
            fn next_block8(&mut self) -> [u64x2; 8] {
                let mut block8 = [u64x2(0, 0); PAR_BLOCKS];
                let mut ctr = self.ctr;
                for i in 0..PAR_BLOCKS {
                    block8[i] = ctr.swap_bytes();
                    ctr.inc_be();
                }
                self.ctr = ctr;

                self.cipher.encrypt_u64x2_8(&mut block8);
                block8
            }
        }
    }
}

impl_ctr!(CtrAes128, Aes128, 16, "AES128 in CTR mode");
impl_ctr!(CtrAes192, Aes192, 24, "AES192 in CTR mode");
impl_ctr!(CtrAes256, Aes256, 32, "AES256 in CTR mode");
