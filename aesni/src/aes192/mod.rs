use u64x2::u64x2;

mod expand;

/// AES-192 block cipher
#[derive(Copy, Clone, Debug)]
pub struct Aes192 {
    encrypt_keys: [u64x2; 13],
    decrypt_keys: [u64x2; 13],
}

impl Aes192 {
    /// Create new AES-192 instance with given key
    #[inline]
    pub fn init(key: &[u8; 24]) -> Self {
        let (encrypt_keys, decrypt_keys) = expand::expand(key);
        Aes192 { encrypt_keys: encrypt_keys, decrypt_keys: decrypt_keys }
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
        let keys = self.decrypt_keys;
        let mut data = u64x2::read(block);
        unsafe {
            asm!(include_str!("decrypt.asm")
                : "+{xmm0}"(data)
                :
                    "{xmm1}"(keys[12]), "{xmm2}"(keys[11]), "{xmm3}"(keys[10]),
                    "{xmm4}"(keys[9]), "{xmm5}"(keys[8]), "{xmm6}"(keys[7]),
                    "{xmm7}"(keys[6]), "{xmm8}"(keys[5]), "{xmm9}"(keys[4]),
                    "{xmm10}"(keys[3]), "{xmm11}"(keys[2]), "{xmm12}"(keys[1]),
                    "{xmm13}"(keys[0])
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
                    "{xmm8}"(keys[12]), "{xmm9}"(keys[11]), "{xmm10}"(keys[10]),
                    "{xmm11}"(keys[9]), "{xmm12}"(keys[8]), "{xmm13}"(keys[7]),
                    "{xmm14}"(keys[6]), "{xmm15}"(keys[5])
                :
                : "intel", "alignstack"
            );

            asm!(include_str!("decrypt8_2.asm")
                :
                    "+{xmm0}"(data[0]), "+{xmm1}"(data[1]), "+{xmm2}"(data[2]),
                    "+{xmm3}"(data[3]), "+{xmm4}"(data[4]), "+{xmm5}"(data[5]),
                    "+{xmm6}"(data[6]), "+{xmm7}"(data[7])
                :
                    "{xmm11}"(keys[4]), "{xmm12}"(keys[3]), "{xmm13}"(keys[2]),
                    "{xmm14}"(keys[1]), "{xmm15}"(keys[0])
                :
                : "intel", "alignstack"
            );
        }
        u64x2::write8(data, blocks);
    }

    #[inline(always)]
    pub(crate) fn encrypt_u64x2(&self, data: &mut u64x2) {
        let keys = self.encrypt_keys;
        unsafe {
            asm!(include_str!("encrypt.asm")
                : "+{xmm0}"(*data)
                :
                    "{xmm1}"(keys[0]), "{xmm2}"(keys[1]), "{xmm3}"(keys[2]),
                    "{xmm4}"(keys[3]), "{xmm5}"(keys[4]), "{xmm6}"(keys[5]),
                    "{xmm7}"(keys[6]), "{xmm8}"(keys[7]), "{xmm9}"(keys[8]),
                    "{xmm10}"(keys[9]), "{xmm11}"(keys[10]), "{xmm12}"(keys[11]),
                    "{xmm13}"(keys[12])
                :
                : "intel", "alignstack"
            );
        }
    }

    #[inline(always)]
    pub(crate) fn encrypt_u64x2_8(&self, data: &mut [u64x2; 8]) {
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
                :
                    "{xmm11}"(keys[8]), "{xmm12}"(keys[9]), "{xmm13}"(keys[10]),
                    "{xmm14}"(keys[11]), "{xmm15}"(keys[12])
                :
                : "intel", "alignstack"
            );
        }
    }
}

#[cfg(test)]
mod test_expand;
