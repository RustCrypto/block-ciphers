#![no_std]
extern crate block_cipher_trait;
extern crate generic_array;

mod consts;

use block_cipher_trait::{Block, BlockCipher, BlockCipherFixKey};
use generic_array::typenum::{U16, U32};

#[derive(Clone,Copy)]
pub struct Kuznyechik {
    keys: [[u8; 16]; 10]
}

fn gf_mul(msg: u8, i: usize) -> u8 {
    match i {
        0 | 7 | 9 => msg,
        4 | 12 => consts::GF[0][msg as usize],
        2 | 14 => consts::GF[1][msg as usize],
        3 | 13 => consts::GF[2][msg as usize],
        1 | 15 => consts::GF[3][msg as usize],
        6 | 10 => consts::GF[4][msg as usize],
        5 | 11 => consts::GF[5][msg as usize],
        8 => consts::GF[6][msg as usize],
        _ => unreachable!(),
    }
}

fn x(a: &mut Block<U16>, b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

fn lsx(msg: &mut Block<U16>, key: &[u8; 16]) {
    x(msg, key);
    // s
    for i in 0..16 {
        msg[i] = consts::P[msg[i] as usize];
    }
    // l
    for j in 0..16 {
        let mut x = msg[j];
        for i in 1..16 {
            let k = (i+j) & 0xf;
            x ^= gf_mul(msg[k], i);
        }
        msg[j] = x;
    }
}

fn lsx_inv(msg: &mut Block<U16>, key: &[u8; 16]) {
    x(msg, key);
    // l_inv
    for j in (0..16).rev() {
        let mut x = msg[j];
        for i in 1..16 {
            let k = (i+j) & 0xf;
            x ^= gf_mul(msg[k], i);
        }
        msg[j] = x;
    }

    // s_inv
    for i in 0..16 {
        msg[i] = consts::P_INV[msg[i] as usize];
    }
}

fn x2(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

fn l2(msg: &mut [u8; 16]) {
    for j in 0..16 {
        let mut x = msg[j];
        for i in 1..16 {
            let k = (i+j) & 0xf;
            x ^= gf_mul(msg[k], i);
        }
        msg[j] = x;
    }
}

fn get_c(n: usize) -> [u8; 16] {
    let mut v = [0u8; 16];
    v[0] = n as u8;
    l2(&mut v);
    v
}

fn lsx2(msg: &mut [u8; 16], key: &[u8; 16]) {
    x2(msg, key);
    // s
    for i in 0..16 {
        msg[i] = consts::P[msg[i] as usize];
    }
    l2(msg);
}

fn f(k1: &mut [u8; 16], k2: &mut [u8; 16], n: usize) {
    for i in 0..4 {
        let mut k1_cpy = k1.clone();
        lsx2(&mut k1_cpy, &get_c(8*n+2*i+1));
        x2(k2, &k1_cpy);

        let mut k2_cpy = k2.clone();
        lsx2(&mut k2_cpy, &get_c(8*n+2*i+2));
        x2(k1, &k2_cpy);        
    }
}

impl Kuznyechik {
    fn expand_key(&mut self, key: &Block<U32>) {

        let mut k1 = [0u8; 16];
        let mut k2 = [0u8; 16];

        k1.copy_from_slice(&key[16..]);
        k2.copy_from_slice(&key[..16]);

        self.keys[0] = k1;
        self.keys[1] = k2;

        for i in 1..5 {
            f(&mut k1, &mut k2, i-1);
            self.keys[2*i] = k1;
            self.keys[2*i+1] = k2;
        }
    }

    fn encrypt(&self, msg: &mut Block<U16>) {
        for k in &self.keys[..9] {
            lsx(msg, k);
        }
        x(msg, &self.keys[9])
    }

    fn decrypt(&self, msg: &mut Block<U16>) {
        for k in self.keys[1..].iter().rev() {
            lsx_inv(msg, k);
        }
        x(msg, &self.keys[0])
    }
}

impl BlockCipher for Kuznyechik {
    type BlockSize = U16;

    fn encrypt_block(&self, input: &Block<U16>, output: &mut Block<U16>) {
        output.clone_from_slice(&input);
        self.encrypt(output);
    }

    fn decrypt_block(&self, input: &Block<U16>, output: &mut Block<U16>) {
        output.clone_from_slice(&input);
        self.decrypt(output);
    }
}

impl BlockCipherFixKey for Kuznyechik {
    type KeySize = U32;

    fn new(key: &Block<U32>) -> Self {
        let mut cipher = Kuznyechik{keys: Default::default()};
        cipher.expand_key(key);
        cipher
    }
}

#[cfg(test)]
mod tests {
    use consts;
    use super::gf_mul;

    #[test]
    fn test_subst_tables() {
        for i in 0..256 {
            assert_eq!(consts::P_INV[consts::P[i] as usize], i as u8);
        }
    }

    fn direct_gf_mul(mut x: u8, mut y: u8) -> u8 {
        let mut z = 0u8;
        while y != 0 {
            if y & 1 == 1 {
               z ^= x;
            }
            if x & 0x80 != 0 {
                x = (x << 1) ^ 0xC3;
            } else {
                x <<= 1;
            }
            y >>= 1;
        }
        z
    }

    #[test]
    fn test_gf_table() {
        for i in 0..16 {
            for j in 0..256 {
                let a = direct_gf_mul(j as u8, consts::L[i]);
                let b = gf_mul(j as u8, i);
                assert_eq!(a, b);
            }
        }
    }
}