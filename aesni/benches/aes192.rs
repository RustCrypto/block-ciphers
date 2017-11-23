#![no_std]
#![cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#![feature(test)]
extern crate aesni;
extern crate test;

#[bench]
pub fn encrypt(bh: &mut test::Bencher) {
    let key = Default::default();
    let cipher = aesni::Aes192::init(&key);
    let mut input = Default::default();

    bh.iter(|| {
        cipher.encrypt(&mut input);
        test::black_box(input);
    });
    bh.bytes = input.len() as u64;
}

#[bench]
pub fn decrypt(bh: &mut test::Bencher) {
    let key = Default::default();
    let cipher = aesni::Aes192::init(&key);
    let mut input = Default::default();

    bh.iter(|| {
        cipher.decrypt(&mut input);
        test::black_box(input);
    });
    bh.bytes = input.len() as u64;
}

#[bench]
pub fn encrypt8(bh: &mut test::Bencher) {
    let key = Default::default();
    let cipher = aesni::Aes192::init(&key);
    let mut input = [0u8; 16*8];

    bh.iter(|| {
        cipher.encrypt8(&mut input);
        test::black_box(input);
    });
    bh.bytes = input.len() as u64;
}

#[bench]
pub fn decrypt8(bh: &mut test::Bencher) {
    let key = Default::default();
    let cipher = aesni::Aes192::init(&key);
    let mut input = [0u8; 16*8];

    bh.iter(|| {
        cipher.decrypt8(&mut input);
        test::black_box(input);
    });
    bh.bytes = input.len() as u64;
}

#[bench]
pub fn ctr_aes192(bh: &mut test::Bencher) {
    let mut cipher = aesni::CtrAes192::new(&[0; 24], &[0; 16]);
    let mut input = [0u8; 10000];

    bh.iter(|| {
        cipher.xor(&mut input);
        test::black_box(&input);
    });
    bh.bytes = input.len() as u64;
}
