#![no_std]
extern crate block_cipher_trait;
extern crate generic_array;

mod consts;
mod expand_key;

use block_cipher_trait::{Block, BlockCipher, BlockCipherFixKey};
use generic_array::typenum::{U16, U32};

#[derive(Clone,Copy)]
pub struct Kuznyechik {
    keys: [[u8; 16]; 10]
}

fn x(a: &mut Block<U16>, b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

fn l_step(msg: &mut Block<U16>, i: usize) {
    let mut x = msg[i];
    x ^= consts::GF[3][msg[(1+i) & 0xf] as usize];
    x ^= consts::GF[1][msg[(2+i) & 0xf] as usize];
    x ^= consts::GF[2][msg[(3+i) & 0xf] as usize];
    x ^= consts::GF[0][msg[(4+i) & 0xf] as usize];
    x ^= consts::GF[5][msg[(5+i) & 0xf] as usize];
    x ^= consts::GF[4][msg[(6+i) & 0xf] as usize];
    x ^= msg[(7+i) & 0xf];
    x ^= consts::GF[6][msg[(8+i) & 0xf] as usize];
    x ^= msg[(9+i) & 0xf];
    x ^= consts::GF[4][msg[(10+i) & 0xf] as usize];
    x ^= consts::GF[5][msg[(11+i) & 0xf] as usize];
    x ^= consts::GF[0][msg[(12+i) & 0xf] as usize];
    x ^= consts::GF[2][msg[(13+i) & 0xf] as usize];
    x ^= consts::GF[1][msg[(14+i) & 0xf] as usize];
    x ^= consts::GF[3][msg[(15+i) & 0xf] as usize];
    msg[i] = x;
}

fn lsx(msg: &mut Block<U16>, key: &[u8; 16]) {
    x(msg, key);
    // s
    for i in 0..16 {
        msg[i] = consts::P[msg[i] as usize];
    }
    // l
    for i in 0..16 {
        l_step(msg, i);
    }
}

fn lsx_inv(msg: &mut Block<U16>, key: &[u8; 16]) {
    x(msg, key);
    // l_inv
    for i in (0..16).rev() {
        l_step(msg, i);
    }
    // s_inv
    for i in 0..16 {
        msg[i] = consts::P_INV[msg[i] as usize];
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
            expand_key::f(&mut k1, &mut k2, i-1);
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
