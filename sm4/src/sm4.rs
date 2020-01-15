use super::generic_array::typenum::{U1, U16};
use super::generic_array::GenericArray;
use super::BlockCipher;
use byteorder::{ByteOrder, BE};

use crate::consts::{CK, FK, SBOX};

#[inline]
fn tau(a: u32) -> u32 {
    let mut buf = [0u8; 4];
    BE::write_u32(&mut buf, a);
    buf[0] = SBOX[buf[0] as usize];
    buf[1] = SBOX[buf[1] as usize];
    buf[2] = SBOX[buf[2] as usize];
    buf[3] = SBOX[buf[3] as usize];
    BE::read_u32(&buf)
}

/// L: linear transformation
#[inline]
fn el(b: u32) -> u32 {
    b ^ b.rotate_left(2) ^ b.rotate_left(10) ^ b.rotate_left(18) ^ b.rotate_left(24)
}

#[inline]
fn el_prime(b: u32) -> u32 {
    b ^ b.rotate_left(13) ^ b.rotate_left(23)
}

#[inline]
fn t(val: u32) -> u32 {
    el(tau(val))
}

#[inline]
fn t_prime(val: u32) -> u32 {
    el_prime(tau(val))
}

#[derive(Copy, Clone)]
pub struct Sm4 {
    rk: [u32; 32],
}

impl BlockCipher for Sm4 {
    type KeySize = U16;
    type BlockSize = U16;
    type ParBlocks = U1;

    fn new(key: &GenericArray<u8, U16>) -> Self {
        let mut mk = [0u32; 4];
        let mut rk = [0u32; 32];
        BE::read_u32_into(key, &mut mk);
        let mut k = [mk[0] ^ FK[0], mk[1] ^ FK[1], mk[2] ^ FK[2], mk[3] ^ FK[3]];

        for i in 0..8 {
            k[0] = k[0] ^ t_prime(k[1] ^ k[2] ^ k[3] ^ CK[i * 4]);
            k[1] = k[1] ^ t_prime(k[2] ^ k[3] ^ k[0] ^ CK[i * 4 + 1]);
            k[2] = k[2] ^ t_prime(k[3] ^ k[0] ^ k[1] ^ CK[i * 4 + 2]);
            k[3] = k[3] ^ t_prime(k[0] ^ k[1] ^ k[2] ^ CK[i * 4 + 3]);
            rk[i * 4 + 0] = k[0];
            rk[i * 4 + 1] = k[1];
            rk[i * 4 + 2] = k[2];
            rk[i * 4 + 3] = k[3];
        }

        Sm4 { rk }
    }

    fn encrypt_block(&self, block: &mut GenericArray<u8, U16>) {
        let mut x = [0u32; 4];
        BE::read_u32_into(block, &mut x);
        let rk = &self.rk;
        for i in 0..8 {
            x[0] = x[0] ^ t(x[1] ^ x[2] ^ x[3] ^ rk[i * 4]);
            x[1] = x[1] ^ t(x[2] ^ x[3] ^ x[0] ^ rk[i * 4 + 1]);
            x[2] = x[2] ^ t(x[3] ^ x[0] ^ x[1] ^ rk[i * 4 + 2]);
            x[3] = x[3] ^ t(x[0] ^ x[1] ^ x[2] ^ rk[i * 4 + 3]);
        }
        x = [x[3], x[2], x[1], x[0]];
        BE::write_u32_into(&x, block);
    }

    fn decrypt_block(&self, block: &mut GenericArray<u8, U16>) {
        let mut x = [0u32; 4];
        BE::read_u32_into(block, &mut x);
        let rk = &self.rk;
        for i in 0..8 {
            x[0] = x[0] ^ t(x[1] ^ x[2] ^ x[3] ^ rk[31 - i * 4]);
            x[1] = x[1] ^ t(x[2] ^ x[3] ^ x[0] ^ rk[31 - (i * 4 + 1)]);
            x[2] = x[2] ^ t(x[3] ^ x[0] ^ x[1] ^ rk[31 - (i * 4 + 2)]);
            x[3] = x[3] ^ t(x[0] ^ x[1] ^ x[2] ^ rk[31 - (i * 4 + 3)]);
        }
        x = [x[3], x[2], x[1], x[0]];
        BE::write_u32_into(&x, block);
    }
}
