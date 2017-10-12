#![no_std]
#![feature(test)]
extern crate aesni;
extern crate test;

#[bench]
pub fn aes128_encrypt(bh: &mut test::Bencher) {
    let cipher = aesni::Aes128::init(&Default::default());
    let mut input = Default::default();

    bh.iter(|| {
        cipher.encrypt(&mut input);
        test::black_box(&input);
    });
    bh.bytes = input.len() as u64;
}

#[bench]
pub fn aes128_decrypt(bh: &mut test::Bencher) {
    let cipher = aesni::Aes128::init(&Default::default());
    let mut input = Default::default();

    bh.iter(|| {
        cipher.decrypt(&mut input);
        test::black_box(&input);
    });
    bh.bytes = input.len() as u64;
}

#[bench]
pub fn aes128_encrypt8(bh: &mut test::Bencher) {
    let cipher = aesni::Aes128::init(&Default::default());
    let mut input = [0u8; 16*8];

    bh.iter(|| {
        cipher.encrypt8(&mut input);
        test::black_box(&input);
    });
    bh.bytes = input.len() as u64;
}

#[bench]
pub fn aes128_decrypt8(bh: &mut test::Bencher) {
    let cipher = aesni::Aes128::init(&Default::default());
    let mut input = [0u8; 16*8];

    bh.iter(|| {
        cipher.decrypt8(&mut input);
        test::black_box(&input);
    });
    bh.bytes = input.len() as u64;
}

#[bench]
pub fn ctr_aes128(bh: &mut test::Bencher) {
    let mut cipher = aesni::CtrAes128::new(&[0; 16], &[0; 16]);
    let mut input = [0u8; 128*100];

    bh.iter(|| {
        cipher.xor(&mut input);
        test::black_box(&input);
    });
    bh.bytes = input.len() as u64;
}
