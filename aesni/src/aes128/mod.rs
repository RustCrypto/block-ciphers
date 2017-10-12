use u64x2::u64x2;
use core::mem;

mod expand;

/// AES-128 block cipher instance
#[derive(Copy, Clone, Debug)]
pub struct Aes128 {
    encrypt_keys: [u64x2; 11],
    decrypt_keys: [u64x2; 11],
}

impl Aes128 {
    /// Create new AES-192 instance with given key
    #[inline]
    pub fn init(key: &[u8; 16]) -> Self {
        let (encrypt_keys, decrypt_keys) = expand::expand(key);
        Aes128 { encrypt_keys: encrypt_keys, decrypt_keys: decrypt_keys }
    }

    /// Encrypt in-place one 128 bit block
    #[inline]
    pub fn encrypt(&self, block: &mut [u8; 16]) {
        let mut data = u64x2::read(block);
        self.encrypt_u64x2(&mut data);
        data.write(block);
    }

    /// Decrypt in-place one 128 bit block
    #[inline]
    pub fn decrypt(&self, block: &mut [u8; 16]) {
        let block: &mut [u8; 16] = unsafe { mem::transmute(block) };
        let keys = self.decrypt_keys;
        let mut data = u64x2::read(block);
        unsafe {
            asm!(include_str!("decrypt.asm")
                : "+{xmm0}"(data)
                :
                    "{xmm1}"(keys[10]), "{xmm2}"(keys[9]), "{xmm3}"(keys[8]),
                    "{xmm4}"(keys[7]), "{xmm5}"(keys[6]), "{xmm6}"(keys[5]),
                    "{xmm7}"(keys[4]), "{xmm8}"(keys[3]), "{xmm9}"(keys[2]),
                    "{xmm10}"(keys[1]), "{xmm11}"(keys[0])
                :
                : "intel", "alignstack"
            );
        }
        data.write(block);
    }

    /// Encrypt in-place eight 128 bit blocks (1024 bits in total) using
    /// instruction-level parallelism
    #[inline]
    pub fn encrypt8(&self, blocks: &mut [u8; 8*16]) {
        let mut data = u64x2::read8(blocks);
        self.encrypt_u64x2_8(&mut data);
        u64x2::write8(data, blocks);
    }

    #[inline(always)]
    fn encrypt_u64x2(&self, block: &mut u64x2) {
        let keys = self.encrypt_keys;
        unsafe {
            asm!(include_str!("encrypt.asm")
                : "+{xmm0}"(*block)
                :
                    "{xmm1}"(keys[0]), "{xmm2}"(keys[1]), "{xmm3}"(keys[2]),
                    "{xmm4}"(keys[3]), "{xmm5}"(keys[4]), "{xmm6}"(keys[5]),
                    "{xmm7}"(keys[6]), "{xmm8}"(keys[7]), "{xmm9}"(keys[8]),
                    "{xmm10}"(keys[9]), "{xmm11}"(keys[10])
                :
                : "intel", "alignstack"
            );
        }
    }

    #[inline(always)]
    fn encrypt_u64x2_8(&self, data: &mut [u64x2; 8]) {
        let keys = self.encrypt_keys;
        unsafe {
            asm!(include_str!("encrypt8_1.asm")
                :
                    "+{xmm0}"(data[0]), "+{xmm1}"(data[1]), "+{xmm2}"(data[2]),
                    "+{xmm3}"(data[3]), "+{xmm4}"(data[4]), "+{xmm5}"(data[5]),
                    "+{xmm6}"(data[6]), "+{xmm7}"(data[7])
                :
                    "{xmm8}"(keys[0]), "{xmm9}"(keys[1]), "{xmm10}"(keys[2]),
                    "{xmm11}"(keys[3]), "{xmm12}"(keys[4]), "{xmm13}"(keys[5]),
                    "{xmm14}"(keys[6]), "{xmm15}"(keys[7])
                :
                : "intel", "alignstack"
            );

            asm!(include_str!("encrypt8_2.asm")
                :
                    "+{xmm0}"(data[0]), "+{xmm1}"(data[1]), "+{xmm2}"(data[2]),
                    "+{xmm3}"(data[3]), "+{xmm4}"(data[4]), "+{xmm5}"(data[5]),
                    "+{xmm6}"(data[6]), "+{xmm7}"(data[7])
                : "{xmm13}"(keys[8]), "{xmm14}"(keys[9]), "{xmm15}"(keys[10])
                :
                : "intel", "alignstack"
            );
        }
    }

    /// Decrypt in-place eight 128 bit blocks (1024 bits in total) using
    /// instruction-level parallelism
    #[inline]
    pub fn decrypt8(&self, blocks: &mut [u8; 8*16]) {
        let keys = self.decrypt_keys;
        let mut data = u64x2::read8(blocks);
        unsafe {
            asm!(include_str!("decrypt8_1.asm")
                :
                    "+{xmm0}"(data[0]), "+{xmm1}"(data[1]), "+{xmm2}"(data[2]),
                    "+{xmm3}"(data[3]), "+{xmm4}"(data[4]), "+{xmm5}"(data[5]),
                    "+{xmm6}"(data[6]), "+{xmm7}"(data[7])
                :
                    "{xmm8}"(keys[10]), "{xmm9}"(keys[9]), "{xmm10}"(keys[8]),
                    "{xmm11}"(keys[7]), "{xmm12}"(keys[6]), "{xmm13}"(keys[5]),
                    "{xmm14}"(keys[4]), "{xmm15}"(keys[3])
                :
                : "intel", "alignstack"
            );

            asm!(include_str!("decrypt8_2.asm")
                :
                    "+{xmm0}"(data[0]), "+{xmm1}"(data[1]), "+{xmm2}"(data[2]),
                    "+{xmm3}"(data[3]), "+{xmm4}"(data[4]), "+{xmm5}"(data[5]),
                    "+{xmm6}"(data[6]), "+{xmm7}"(data[7])
                : "{xmm13}"(keys[2]), "{xmm14}"(keys[1]), "{xmm15}"(keys[0])
                :
                : "intel", "alignstack"
            );
        }
        u64x2::write8(data, blocks);
    }
}


const BLOCK_SIZE: usize = 16;
const PAR_BLOCKS: usize = 8;
const PAR_BLOCKS_SIZE: usize = PAR_BLOCKS*BLOCK_SIZE;

pub struct CtrAes128 {
    ctr: u64x2,
    cipher: Aes128,

    leftover_buf: [u8; BLOCK_SIZE],
    leftover_cursor: usize,
}

#[inline(always)]
fn xor_ctr(buf: &mut [u8], ctr: [u64x2; 8]) {
    assert_eq!(buf.len(), PAR_BLOCKS_SIZE);
    let t = unsafe {
        &mut *(buf.as_mut_ptr() as *mut [u64x2; PAR_BLOCKS])
    };
    for i in 0..PAR_BLOCKS {
        t[i].0 ^= ctr[i].0;
        t[i].1 ^= ctr[i].1;
    }
}

impl CtrAes128 {
    pub fn new(key: &[u8; 16], nonce: &[u8; 16]) -> Self {
        let ctr = u64x2::read(nonce).swap_bytes();
        let cipher = Aes128::init(key);
        Self{
            ctr, cipher,
            leftover_cursor: BLOCK_SIZE,
            leftover_buf: [0u8; BLOCK_SIZE]
        }
    }

    pub fn xor(&mut self, mut buf: &mut [u8]) {
        // process leftover bytes from the last call if any
        if self.leftover_cursor != BLOCK_SIZE {
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
            xor_ctr(r, self.next_block8());
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
                 mem::transmute::<u64x2, [u8; 16]>(block)
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

#[cfg(test)]
mod test_expand;
