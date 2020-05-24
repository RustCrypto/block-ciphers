#![no_std]
#![feature(test)]
//#[macro_use]
//extern crate crypto_tests;
extern crate threefish;

extern crate block_cipher_trait;
extern crate generic_array;
extern crate test;

use block_cipher_trait::BlockCipher;
use generic_array::GenericArray;
use test::Bencher;

#[bench]
pub fn encrypt_1_256(bh: &mut Bencher) {
    let key = Default::default();
    let tweak = Default::default();
    let state = threefish::Threefish256::new(&key, &tweak);
    let input = &[1u8; 32];
    let mut output = GenericArray::default();

    bh.iter(|| {
        state.encrypt_block(GenericArray::from_slice(input), &mut output);
    });
    bh.bytes = 32u64;
}

#[bench]
pub fn encrypt_2_512(bh: &mut Bencher) {
    let key = [0u8; 64];
    let tweak = Default::default();
    let state = threefish::Threefish512::new(&key, &tweak);
    let input = &[1u8; 64];
    let mut output = GenericArray::default();

    bh.iter(|| {
        state.encrypt_block(GenericArray::from_slice(input), &mut output);
    });
    bh.bytes = 64u64;
}

#[bench]
pub fn encrypt_3_1024(bh: &mut Bencher) {
    let key = [0u8; 128];
    let tweak = Default::default();
    let state = threefish::Threefish1024::new(&key, &tweak);
    let input = &[1u8; 128];
    let mut output = GenericArray::default();

    bh.iter(|| {
        state.encrypt_block(GenericArray::from_slice(input), &mut output);
    });
    bh.bytes = 128u64;
}
