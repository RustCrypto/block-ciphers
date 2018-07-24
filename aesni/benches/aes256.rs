#![no_std]
#![cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#![feature(test)]
extern crate aesni;
extern crate test;

use aesni::{Aes256, BlockCipher};

#[bench]
pub fn aes256_encrypt(bh: &mut test::Bencher) {
    let cipher = Aes256::new(&Default::default());
    let mut input = Default::default();

    bh.iter(|| {
        cipher.encrypt_block(&mut input);
        test::black_box(&input);
    });
    bh.bytes = input.len() as u64;
}

#[bench]
pub fn aes256_decrypt(bh: &mut test::Bencher) {
    let cipher = Aes256::new(&Default::default());
    let mut input = Default::default();

    bh.iter(|| {
        cipher.decrypt_block(&mut input);
        test::black_box(&input);
    });
    bh.bytes = input.len() as u64;
}

#[bench]
pub fn aes256_encrypt8(bh: &mut test::Bencher) {
    let cipher = Aes256::new(&Default::default());
    let mut input = Default::default();

    bh.iter(|| {
        cipher.encrypt_blocks(&mut input);
        test::black_box(&input);
    });
    bh.bytes = (input[0].len() * input.len()) as u64;
}

#[bench]
pub fn aes256_decrypt8(bh: &mut test::Bencher) {
    let cipher = Aes256::new(&Default::default());
    let mut input = Default::default();

    bh.iter(|| {
        cipher.decrypt_blocks(&mut input);
        test::black_box(&input);
    });
    bh.bytes = (input[0].len() * input.len()) as u64;
}

#[cfg(feature = "ctr")]
#[bench]
pub fn ctr_aes256(bh: &mut test::Bencher) {
    use aesni::stream_cipher::{StreamCipherCore, NewFixStreamCipher};
    let key = Default::default();
    let mut cipher = aesni::Aes256Ctr::new(&key, &Default::default());
    let mut input = [0u8; 10000];


    bh.iter(|| {
        cipher.apply_keystream(&mut input);
        test::black_box(&input);
    });
    bh.bytes = input.len() as u64;
}
