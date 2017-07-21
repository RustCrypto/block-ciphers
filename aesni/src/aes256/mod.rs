use core::mem::transmute;
use super::u64x2;

mod expand;

#[derive(Copy, Clone, Debug)]
pub struct Aes256 {
    encrypt_keys: [u64x2; 15],
    decrypt_keys: [u64x2; 15],
}

impl Aes256 {
    #[inline]
    pub fn new(key: &[u8; 32]) -> Self {
        let (encrypt_keys, decrypt_keys) = expand::expand(key);
        Aes256 { encrypt_keys: encrypt_keys, decrypt_keys: decrypt_keys }
    }

    #[inline]
    pub fn encrypt(&self, block: &mut [u8; 16]) {
        assert!((block.as_ptr() as usize) % 16 == 0, "unaligned input");
        let keys = self.encrypt_keys;
        unsafe {
            let mut data: &mut u64x2 = transmute(block);

            asm!(include_str!("encrypt.asm")
                : "+{xmm0}"(*data)
                :
                    "{xmm1}"(keys[0]), "{xmm2}"(keys[1]), "{xmm3}"(keys[2]),
                    "{xmm4}"(keys[3]), "{xmm5}"(keys[4]), "{xmm6}"(keys[5]),
                    "{xmm7}"(keys[6]), "{xmm8}"(keys[7]), "{xmm9}"(keys[8]),
                    "{xmm10}"(keys[9]), "{xmm11}"(keys[10]), "{xmm12}"(keys[11]),
                    "{xmm13}"(keys[12]), "{xmm14}"(keys[13]), "{xmm15}"(keys[14])
                :
                : "intel", "alignstack"
            );
        }
    }

    #[inline]
    pub fn decrypt(&self, block: &mut [u8; 16]) {
        assert!((block.as_ptr() as usize) % 16 == 0, "unaligned input");
        let keys = self.decrypt_keys;
        unsafe {
            let mut data: &mut u64x2 = transmute(block);

            asm!(include_str!("decrypt.asm")
                : "+{xmm0}"(*data)
                :
                    "{xmm1}"(keys[14]), "{xmm2}"(keys[13]), "{xmm3}"(keys[12]),
                    "{xmm4}"(keys[11]), "{xmm5}"(keys[10]), "{xmm6}"(keys[9]),
                    "{xmm7}"(keys[8]), "{xmm8}"(keys[7]), "{xmm9}"(keys[6]),
                    "{xmm10}"(keys[5]), "{xmm11}"(keys[4]), "{xmm12}"(keys[3]),
                    "{xmm13}"(keys[2]), "{xmm14}"(keys[1]), "{xmm15}"(keys[0])
                :
                : "intel", "alignstack"
            );
        }
    }

    #[inline]
    pub fn encrypt8(&self, blocks: &mut [u8; 8*16]) {
        assert!((blocks.as_ptr() as usize) % 16 == 0, "unaligned input");
        let keys = self.encrypt_keys;
        unsafe {
            let mut data: &mut [u64x2; 8] = transmute(blocks);

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
                :
                    "{xmm9}"(keys[8]), "{xmm10}"(keys[9]), "{xmm11}"(keys[10]),
                    "{xmm12}"(keys[11]), "{xmm13}"(keys[12]), "{xmm14}"(keys[13]),
                    "{xmm15}"(keys[14])
                :
                : "intel", "alignstack"
            );
        }
    }

    #[inline]
    pub fn decrypt8(&self, blocks: &mut [u8; 8*16]) {
        assert!((blocks.as_ptr() as usize) % 16 == 0, "unaligned input");
        let keys = self.decrypt_keys;
        unsafe {
            let mut data: &mut [u64x2; 8] = transmute(blocks);

            asm!(include_str!("decrypt8_1.asm")
                :
                    "+{xmm0}"(data[0]), "+{xmm1}"(data[1]), "+{xmm2}"(data[2]),
                    "+{xmm3}"(data[3]), "+{xmm4}"(data[4]), "+{xmm5}"(data[5]),
                    "+{xmm6}"(data[6]), "+{xmm7}"(data[7])
                :
                    "{xmm8}"(keys[14]), "{xmm9}"(keys[13]), "{xmm10}"(keys[12]),
                    "{xmm11}"(keys[11]), "{xmm12}"(keys[10]), "{xmm13}"(keys[9]),
                    "{xmm14}"(keys[8]), "{xmm15}"(keys[7])
                :
                : "intel", "alignstack"
            );

            asm!(include_str!("decrypt8_2.asm")
                :
                    "+{xmm0}"(data[0]), "+{xmm1}"(data[1]), "+{xmm2}"(data[2]),
                    "+{xmm3}"(data[3]), "+{xmm4}"(data[4]), "+{xmm5}"(data[5]),
                    "+{xmm6}"(data[6]), "+{xmm7}"(data[7])
                :
                    "{xmm9}"(keys[6]), "{xmm10}"(keys[5]), "{xmm11}"(keys[4]),
                    "{xmm12}"(keys[3]), "{xmm13}"(keys[2]), "{xmm14}"(keys[1]),
                    "{xmm15}"(keys[0])
                :
                : "intel", "alignstack"
            );
        }
    }
}

#[cfg(test)]
mod test_expand;
