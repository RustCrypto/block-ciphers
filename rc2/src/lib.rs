//! An implementation of the [RC2][1] block cipher.
//!
//! [1]: https://en.wikipedia.org/wiki/RC2
#![no_std]
pub extern crate block_cipher_trait;
#[macro_use] extern crate opaque_debug;

use block_cipher_trait::BlockCipher;
use block_cipher_trait::InvalidKeyLength;
use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::generic_array::typenum::{U1, U32, U8};

mod consts;
use consts::PI_TABLE;

/// A structure that represents the block cipher initialized with a key
pub struct Rc2 {
    exp_key: [u16; 64],
}

impl Rc2 {
    /// Create a cipher with the specified effective key length
    pub fn new_with_eff_key_len(key: &[u8], eff_key_len: usize) -> Self {
        Self {
            exp_key: Rc2::expand_key(key, eff_key_len),
        }
    }

    fn expand_key(key: &[u8], t1: usize) -> [u16; 64] {
        let key_len = key.len() as usize;

        let t8: usize = (t1 + 7) >> 3;

        let tm: usize =
            (255 % ((2 as u32).pow((8 + t1 - 8 * t8) as u32))) as usize;

        let mut key_buffer: [u8; 128] = [0; 128];
        key_buffer[..key_len].copy_from_slice(&key[..key_len]);

        for i in key_len..128 {
            let pos: u32 = (u32::from(key_buffer[i - 1])
                + u32::from(key_buffer[i - key_len]))
                & 0xff;
            key_buffer[i] = PI_TABLE[pos as usize];
        }

        key_buffer[128 - t8] =
            PI_TABLE[(key_buffer[128 - t8] & tm as u8) as usize];

        for i in (0..128 - t8).rev() {
            let pos: usize = (key_buffer[i + 1] ^ key_buffer[i + t8]) as usize;
            key_buffer[i] = PI_TABLE[pos];
        }

        let mut result: [u16; 64] = [0; 64];
        for i in 0..64 {
            result[i] = (u16::from(key_buffer[2 * i + 1]) << 8)
                + u16::from(key_buffer[2 * i])
        }
        result
    }

    fn mix(&self, r: &mut [u16; 4], j: &mut usize) {
        r[0] = r[0].wrapping_add(self.exp_key[*j])
            .wrapping_add(r[3] & r[2])
            .wrapping_add(!r[3] & r[1]);
        *j += 1;
        r[0] = (r[0] << 1) | (r[0] >> 15);

        r[1] = r[1].wrapping_add(self.exp_key[*j])
            .wrapping_add(r[0] & r[3])
            .wrapping_add(!r[0] & r[2]);
        *j += 1;
        r[1] = (r[1] << 2) | (r[1] >> 14);

        r[2] = r[2].wrapping_add(self.exp_key[*j])
            .wrapping_add(r[1] & r[0])
            .wrapping_add(!r[1] & r[3]);
        *j += 1;
        r[2] = (r[2] << 3) | (r[2] >> 13);

        r[3] = r[3].wrapping_add(self.exp_key[*j])
            .wrapping_add(r[2] & r[1])
            .wrapping_add(!r[2] & r[0]);
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
        r[3] = r[3].wrapping_sub(self.exp_key[*j])
            .wrapping_sub(r[2] & r[1])
            .wrapping_sub(!r[2] & r[0]);
        *j -= 1;

        r[2] = (r[2] << 13) | (r[2] >> 3);
        r[2] = r[2].wrapping_sub(self.exp_key[*j])
            .wrapping_sub(r[1] & r[0])
            .wrapping_sub(!r[1] & r[3]);
        *j -= 1;

        r[1] = (r[1] << 14) | (r[1] >> 2);
        r[1] = r[1].wrapping_sub(self.exp_key[*j])
            .wrapping_sub(r[0] & r[3])
            .wrapping_sub(!r[0] & r[2]);
        *j -= 1;

        r[0] = (r[0] << 15) | (r[0] >> 1);
        r[0] = r[0].wrapping_sub(self.exp_key[*j])
            .wrapping_sub(r[3] & r[2])
            .wrapping_sub(!r[3] & r[1]);
        *j = j.wrapping_sub(1);
    }

    fn reverse_mash(&self, r: &mut [u16; 4]) {
        r[3] = r[3].wrapping_sub(self.exp_key[(r[2] & 63) as usize]);
        r[2] = r[2].wrapping_sub(self.exp_key[(r[1] & 63) as usize]);
        r[1] = r[1].wrapping_sub(self.exp_key[(r[0] & 63) as usize]);
        r[0] = r[0].wrapping_sub(self.exp_key[(r[3] & 63) as usize]);
    }

    fn encrypt(&self, block: &mut GenericArray<u8, U8>) {
        let mut r: [u16; 4] = [
            (u16::from(block[1]) << 8) + u16::from(block[0]),
            (u16::from(block[3]) << 8) + u16::from(block[2]),
            (u16::from(block[5]) << 8) + u16::from(block[4]),
            (u16::from(block[7]) << 8) + u16::from(block[6]),
        ];

        let mut j = 0;

        for i in 0..16 {
            self.mix(&mut r, &mut j);
            if i == 4 || i == 10 {
                self.mash(&mut r);
            }
        }

        block[0] = (r[0] & 0xff) as u8;
        block[1] = (r[0] >> 8) as u8;
        block[2] = (r[1] & 0xff) as u8;
        block[3] = (r[1] >> 8) as u8;
        block[4] = (r[2] & 0xff) as u8;
        block[5] = (r[2] >> 8) as u8;
        block[6] = (r[3] & 0xff) as u8;
        block[7] = (r[3] >> 8) as u8;
    }

    fn decrypt(&self, block: &mut GenericArray<u8, U8>) {
        let mut r: [u16; 4] = [
            (u16::from(block[1]) << 8) + u16::from(block[0]),
            (u16::from(block[3]) << 8) + u16::from(block[2]),
            (u16::from(block[5]) << 8) + u16::from(block[4]),
            (u16::from(block[7]) << 8) + u16::from(block[6]),
        ];

        let mut j = 63;

        for i in 0..16 {
            self.reverse_mix(&mut r, &mut j);
            if i == 4 || i == 10 {
                self.reverse_mash(&mut r);
            }
        }

        block[0] = r[0] as u8;
        block[1] = (r[0] >> 8) as u8;
        block[2] = r[1] as u8;
        block[3] = (r[1] >> 8) as u8;
        block[4] = r[2] as u8;
        block[5] = (r[2] >> 8) as u8;
        block[6] = r[3] as u8;
        block[7] = (r[3] >> 8) as u8;
    }
}

impl BlockCipher for Rc2 {
    type KeySize = U32;
    type BlockSize = U8;
    type ParBlocks = U1;

    fn new(key: &GenericArray<u8, U32>) -> Self {
        Self::new_varkey(key).unwrap()
    }

    fn new_varkey(key: &[u8]) -> Result<Self, InvalidKeyLength> {
        if key.is_empty() || key.len() > 128 {
            Err(InvalidKeyLength)
        } else {
            Ok(Self::new_with_eff_key_len(key, key.len() * 8))
        }
    }

    fn encrypt_block(&self, block: &mut GenericArray<u8, U8>) {
        self.encrypt(block);
    }

    fn decrypt_block(&self, block: &mut GenericArray<u8, U8>) {
        self.decrypt(block);
    }
}

impl_opaque_debug!(Rc2);
