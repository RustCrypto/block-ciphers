use u64x2::u64x2;

mod expand;

#[derive(Copy, Clone, Debug)]
pub struct Aes128 {
    encrypt_keys: [u64x2; 11],
    decrypt_keys: [u64x2; 11],
}

impl Aes128 {
    #[inline]
    pub fn new(key: &[u8; 16]) -> Self {
        let (encrypt_keys, decrypt_keys) = expand::expand(key);
        Aes128 { encrypt_keys: encrypt_keys, decrypt_keys: decrypt_keys }
    }

    #[inline]
    pub fn encrypt(&self, block: &mut [u8; 16]) {
        let keys = self.encrypt_keys;
        let mut data = u64x2::read(block);
        unsafe {
            asm!(include_str!("encrypt.asm")
                : "+{xmm0}"(data)
                :
                    "{xmm1}"(keys[0]), "{xmm2}"(keys[1]), "{xmm3}"(keys[2]),
                    "{xmm4}"(keys[3]), "{xmm5}"(keys[4]), "{xmm6}"(keys[5]),
                    "{xmm7}"(keys[6]), "{xmm8}"(keys[7]), "{xmm9}"(keys[8]),
                    "{xmm10}"(keys[9]), "{xmm11}"(keys[10])
                :
                : "intel", "alignstack"
            );
        }
        data.write(block);
    }

    #[inline]
    pub fn decrypt(&self, block: &mut [u8; 16]) {
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

    #[inline]
    pub fn encrypt8(&self, blocks: &mut [u8; 8*16]) {
        let keys = self.encrypt_keys;
        let mut data = u64x2::read8(blocks);
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
        u64x2::write8(data, blocks);
    }

    #[inline]
    pub fn decrypt8(&self, blocks: &mut [u8; 8*16]) {
        assert!((blocks.as_ptr() as usize) % 16 == 0, "unaligned input");
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

#[cfg(test)]
mod test_expand;
