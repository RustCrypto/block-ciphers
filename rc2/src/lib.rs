#![no_std]
extern crate block_cipher_trait;
extern crate generic_array;
extern crate byte_tools;

use block_cipher_trait::{Block, BlockCipher, BlockCipherVarKey};
use generic_array::typenum::U8;

mod consts;
use consts::PITABLE;


pub struct RC2 {
    exp_key: [u16; 64],
}

impl RC2 {
    pub fn new_with_effective_key_length(key: &[u8], eff_key_len: usize) -> RC2 {
        RC2 {
            exp_key: RC2::expand_key(key, eff_key_len)
        }
    }

    fn expand_key(key: &[u8], t1: usize) -> [u16; 64] {
        let key_len = key.len() as usize;

        //let t1: usize = key_len<<3;
        let t8: usize = (t1+7)>>3;

        let tm: usize = (255 % ((2 as u32).pow((8+t1-8*t8) as u32))) as usize;

        let mut key_buffer: [u8; 128] = [0; 128];
        for i in 0..key_len {
            key_buffer[i] = key[i];
        }

        for i in key_len..128 {
            let pos: u32 = (key_buffer[i-1] as u32 + key_buffer[i-key_len] as u32) & 0xff;
            key_buffer[i] = PITABLE[pos as usize];
        }

        key_buffer[128-t8] = PITABLE[(key_buffer[128-t8] & tm as u8) as usize];

        for i in (0..128-t8).rev() {
            let pos: usize = (key_buffer[i+1] ^ key_buffer[i+t8]) as usize;
            key_buffer[i] = PITABLE[pos];
        }

        let mut result: [u16; 64] = [0; 64];
        for i in 0..64 {
            result[i] = ((key_buffer[2*i+1] as u16) << 8) + (key_buffer[2*i] as u16)
        }
        result
    }

    fn mix(&self, r: &mut [u16; 4], j: &mut usize) {
        r[0] = r[0].wrapping_add(self.exp_key[*j]).wrapping_add(r[3] & r[2]).wrapping_add(!r[3] & r[1]);
        *j += 1;
        r[0] = (r[0] << 1) | (r[0] >> 15);

        r[1] = r[1].wrapping_add(self.exp_key[*j]).wrapping_add(r[0] & r[3]).wrapping_add(!r[0] & r[2]);
        *j += 1;
        r[1] = (r[1] << 2) | (r[1] >> 14);

        r[2] = r[2].wrapping_add(self.exp_key[*j]).wrapping_add(r[1] & r[0]).wrapping_add(!r[1] & r[3]);
        *j += 1;
        r[2] = (r[2] << 3) | (r[2] >> 13);

        r[3] = r[3].wrapping_add(self.exp_key[*j]).wrapping_add(r[2] & r[1]).wrapping_add(!r[2] & r[0]);
        *j += 1;
        r[3] = (r[3] << 5) | (r[3] >> 11);
    }

    fn mash(&self, r: &mut [u16; 4]) {
        r[0] = r[0].wrapping_add(self.exp_key[(r[3] & 63) as usize]);
        r[1] = r[1].wrapping_add(self.exp_key[(r[0] & 63) as usize]);
        r[2] = r[2].wrapping_add(self.exp_key[(r[1] & 63) as usize]);
        r[3] = r[3].wrapping_add(self.exp_key[(r[2] & 63) as usize]);
    }

    fn reverse_mix(&self, r: &mut [u16; 4], j: &mut usize) {
        r[3] = (r[3] << 11) | (r[3] >> 5);
        r[3] = r[3].wrapping_sub(self.exp_key[*j]).wrapping_sub(r[2] & r[1]).wrapping_sub(!r[2] & r[0]);
        *j -= 1;

        r[2] = (r[2] << 13) | (r[2] >> 3);
        r[2] = r[2].wrapping_sub(self.exp_key[*j]).wrapping_sub(r[1] & r[0]).wrapping_sub(!r[1] & r[3]);
        *j -= 1;

        r[1] = (r[1] << 14) | (r[1] >> 2);
        r[1] = r[1].wrapping_sub(self.exp_key[*j]).wrapping_sub(r[0] & r[3]).wrapping_sub(!r[0] & r[2]);
        *j -= 1;

        r[0] = (r[0] << 15) | (r[0] >> 1);
        r[0] = r[0].wrapping_sub(self.exp_key[*j]).wrapping_sub(r[3] & r[2]).wrapping_sub(!r[3] & r[1]);
        *j = j.wrapping_sub(1);
    }

    fn reverse_mash(&self, r: &mut [u16; 4]) {
        r[3] = r[3].wrapping_sub(self.exp_key[(r[2] & 63) as usize]);
        r[2] = r[2].wrapping_sub(self.exp_key[(r[1] & 63) as usize]);
        r[1] = r[1].wrapping_sub(self.exp_key[(r[0] & 63) as usize]);
        r[0] = r[0].wrapping_sub(self.exp_key[(r[3] & 63) as usize]);
    }

    fn encrypt(&self, block: [u8; 8]) -> [u8; 8] {
        let mut r: [u16; 4] = [0; 4];

        r[0] = ((block[1] as u16) << 8) + (block[0] as u16);
        r[1] = ((block[3] as u16) << 8) + (block[2] as u16);
        r[2] = ((block[5] as u16) << 8) + (block[4] as u16);
        r[3] = ((block[7] as u16) << 8) + (block[6] as u16);

        let mut j = 0;

        for i in 0..16 {
            self.mix(&mut r, &mut j);
            if i == 4 || i == 10 {
                self.mash(&mut r);
            }
        }

        let mut ct: [u8; 8] = [0; 8];
        ct[0] = r[0] as u8;
        ct[1] = (r[0] >> 8) as u8;
        ct[2] = r[1] as u8;
        ct[3] = (r[1] >> 8) as u8;
        ct[4] = r[2] as u8;
        ct[5] = (r[2] >> 8) as u8;
        ct[6] = r[3] as u8;
        ct[7] = (r[3] >> 8) as u8;

        ct
    }

    fn decrypt(&self, block: [u8; 8]) -> [u8; 8] {
        let mut r: [u16; 4] = [0; 4];

        r[0] = ((block[1] as u16) << 8) + (block[0] as u16);
        r[1] = ((block[3] as u16) << 8) + (block[2] as u16);
        r[2] = ((block[5] as u16) << 8) + (block[4] as u16);
        r[3] = ((block[7] as u16) << 8) + (block[6] as u16);

        let mut j = 63;

        for i in 0..16 {
            self.reverse_mix(&mut r, &mut j);
            if i == 4 || i == 10 {
                self.reverse_mash(&mut r);
            }
        }

        let mut ct: [u8; 8] = [0; 8];
        ct[0] = r[0] as u8;
        ct[1] = (r[0] >> 8) as u8;
        ct[2] = r[1] as u8;
        ct[3] = (r[1] >> 8) as u8;
        ct[4] = r[2] as u8;
        ct[5] = (r[2] >> 8) as u8;
        ct[6] = r[3] as u8;
        ct[7] = (r[3] >> 8) as u8;

        ct
    }
}

impl BlockCipherVarKey for RC2 {
    fn new(key: &[u8]) -> RC2 {
        RC2 {
            exp_key: RC2::expand_key(key, key.len()*8)
        }
    }
}

impl BlockCipher for RC2 {
    type BlockSize = U8;

    fn encrypt_block(&self, input: &Block<U8>, output: &mut Block<U8>) {
        let mut iblock: [u8; 8] = [0; 8];
        for i in 0..8 {
            iblock[i] = input[i];
        }
        let oblock = self.encrypt(iblock);
        for i in 0..8 {
            output[i] = oblock[i];
        }
    }

    fn decrypt_block(&self, input: &Block<U8>, output: &mut Block<U8>) {
        let mut iblock: [u8; 8] = [0; 8];
        for i in 0..8 {
            iblock[i] = input[i];
        }
        let oblock = self.decrypt(iblock);
        for i in 0..8 {
            output[i] = oblock[i];
        }
    }
}
