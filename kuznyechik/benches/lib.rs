#![no_std]
#![feature(test)]
extern crate kuznyechik;

extern crate test;
extern crate block_cipher_trait;
extern crate generic_array;

use test::Bencher;
use block_cipher_trait::{BlockCipher, BlockCipherFixKey};
use generic_array::GenericArray;

#[bench]
pub fn encrypt(bh: &mut Bencher) {
    let key = Default::default();
    let state = kuznyechik::Kuznyechik::new(&key);

    let data = [1u8; 16];
    let input = GenericArray::from_slice(&data);
    let mut output = GenericArray::default();

    bh.iter(|| {
        state.encrypt_block(input, &mut output);
    });
    bh.bytes = 16u64;
}
