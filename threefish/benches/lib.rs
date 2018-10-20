#![no_std]
#![feature(test)]
extern crate threefish;

extern crate test;
extern crate block_cipher_trait;
extern crate generic_array;

use test::Bencher;
use block_cipher_trait::BlockCipher;
use generic_array::GenericArray;

#[bench]
pub fn encrypt_1_256(bh: &mut Bencher) {
    let key = Default::default();
    let tweak = Default::default();
    let state = threefish::Threefish256::with_tweak(&key, &tweak);
    let input = &[1u8; 32];
    bh.iter(|| {
        state.encrypt_block(mut GenericArray::from_slice(input));
    });
    bh.bytes = 32u64;
}

#[bench]
pub fn encrypt_2_512(bh: &mut Bencher) {
    let key = Default::default();
    let tweak = Default::default();
    let state = threefish::Threefish512::with_tweak(&key, &tweak);
    let input = &[1u8; 64];
    bh.iter(|| {
        state.encrypt_block(mut GenericArray::from_slice(input));
    });
    bh.bytes = 64u64;
}

#[bench]
pub fn encrypt_3_1024(bh: &mut Bencher) {
    let key = Default::default();
    let tweak = Default::default();
    let state = threefish::Threefish1024::with_tweak(&key, &tweak);
    let input = &[1u8; 128];
    bh.iter(|| {
        state.encrypt_block(mut GenericArray::from_slice(input));
    });
    bh.bytes = 128u64;
}
