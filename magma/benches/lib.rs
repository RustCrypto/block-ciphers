#![no_std]
#![feature(test)]
#[macro_use]
extern crate crypto_tests;
extern crate magma;

extern crate test;
extern crate block_cipher_trait;
extern crate generic_array;

use test::Bencher;
use block_cipher_trait::{BlockCipher, BlockCipherFixKey};
use generic_array::GenericArray;

#[bench]
pub fn encrypt(bh: &mut Bencher) {
    let key = Default::default();
    let state = magma::Magma::new(&key);
    let input = &[1u8; 8];
    let mut output = GenericArray::default();

    bh.iter(|| {
        state.encrypt_block(GenericArray::from_slice(input), &mut output);
    });
    bh.bytes = 8u64;
}
