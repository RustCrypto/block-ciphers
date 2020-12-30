#![feature(test)]

extern crate test;

use cipher::{generic_array::GenericArray, BlockEncrypt, NewBlockCipher};
use test::Bencher;

#[bench]
pub fn encrypt_1_256(bh: &mut Bencher) {
    let key = Default::default();
    let state = threefish::Threefish256::new(&key);
    let input = &[1u8; 32];

    bh.iter(|| {
        state.encrypt_block(&mut GenericArray::clone_from_slice(input));
    });
    bh.bytes = 32u64;
}

#[bench]
pub fn encrypt_2_512(bh: &mut Bencher) {
    let key = Default::default();
    let state = threefish::Threefish512::new(&key);
    let input = &[1u8; 64];

    bh.iter(|| {
        state.encrypt_block(&mut GenericArray::clone_from_slice(input));
    });
    bh.bytes = 64u64;
}

#[bench]
pub fn encrypt_3_1024(bh: &mut Bencher) {
    let key = Default::default();
    let state = threefish::Threefish1024::new(&key);
    let input = &[1u8; 128];

    bh.iter(|| {
        state.encrypt_block(&mut GenericArray::clone_from_slice(input));
    });
    bh.bytes = 128u64;
}
