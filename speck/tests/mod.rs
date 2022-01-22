//! Test vectors are from The Simon and Speck Families of Lightweight Block Ciphers (Appendix C)

use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use hex_literal::hex;
use speck::{
    Speck128_128, Speck128_192, Speck128_256, Speck32_64, Speck48_72, Speck48_96, Speck64_128,
    Speck64_96, Speck96_144, Speck96_96,
};

#[test]
fn speck32_64() {
    let key = hex!("1918111009080100");
    let plaintext = hex!("6574694c");
    let ciphertext = hex!("a86842f2");
    let cipher = Speck32_64::new(&key.into());

    let mut block = plaintext.clone().into();
    cipher.encrypt_block(&mut block);

    assert_eq!(&ciphertext, block.as_slice());

    cipher.decrypt_block(&mut block);
    assert_eq!(&plaintext, block.as_slice());
}

#[test]
fn speck48_72() {
    let key = hex!("1211100a0908020100");
    let plaintext = hex!("20796c6c6172");
    let ciphertext = hex!("c049a5385adc");
    let cipher = Speck48_72::new(&key.into());

    let mut block = plaintext.clone().into();
    cipher.encrypt_block(&mut block);

    assert_eq!(&ciphertext, block.as_slice());

    cipher.decrypt_block(&mut block);
    assert_eq!(&plaintext, block.as_slice());
}

#[test]
fn speck48_96() {
    let key = hex!("1a19181211100a0908020100");
    let plaintext = hex!("6d2073696874");
    let ciphertext = hex!("735e10b6445d");
    let cipher = Speck48_96::new(&key.into());

    let mut block = plaintext.clone().into();
    cipher.encrypt_block(&mut block);

    assert_eq!(&ciphertext, block.as_slice());

    cipher.decrypt_block(&mut block);
    assert_eq!(&plaintext, block.as_slice());
}

#[test]
fn speck64_96() {
    let key = hex!("131211100b0a090803020100");
    let plaintext = hex!("74614620736e6165");
    let ciphertext = hex!("9f7952ec4175946c");
    let cipher = Speck64_96::new(&key.into());

    let mut block = plaintext.clone().into();
    cipher.encrypt_block(&mut block);

    assert_eq!(&ciphertext, block.as_slice());

    cipher.decrypt_block(&mut block);
    assert_eq!(&plaintext, block.as_slice());
}

#[test]
fn speck64_128() {
    let key = hex!("1b1a1918131211100b0a090803020100");
    let plaintext = hex!("3b7265747475432d");
    let ciphertext = hex!("8c6fa548454e028b");
    let cipher = Speck64_128::new(&key.into());

    let mut block = plaintext.clone().into();
    cipher.encrypt_block(&mut block);

    assert_eq!(&ciphertext, block.as_slice());

    cipher.decrypt_block(&mut block);
    assert_eq!(&plaintext, block.as_slice());
}

#[test]
fn speck96_96() {
    let key = hex!("0d0c0b0a0908050403020100");
    let plaintext = hex!("65776f68202c656761737520");
    let ciphertext = hex!("9e4d09ab717862bdde8f79aa");
    let cipher = Speck96_96::new(&key.into());

    let mut block = plaintext.clone().into();
    cipher.encrypt_block(&mut block);

    assert_eq!(&ciphertext, block.as_slice());

    cipher.decrypt_block(&mut block);
    assert_eq!(&plaintext, block.as_slice());
}

#[test]
fn speck96_144() {
    let key = hex!("1514131211100d0c0b0a0908050403020100");
    let plaintext = hex!("656d6974206e69202c726576");
    let ciphertext = hex!("2bf31072228a 7ae440252ee6");
    let cipher = Speck96_144::new(&key.into());

    let mut block = plaintext.clone().into();
    cipher.encrypt_block(&mut block);

    assert_eq!(&ciphertext, block.as_slice());

    cipher.decrypt_block(&mut block);
    assert_eq!(&plaintext, block.as_slice());
}

#[test]
fn speck128_128() {
    let key = hex!("0f0e0d0c0b0a09080706050403020100");
    let plaintext = hex!("6c617669757165207469206564616d20");
    let ciphertext = hex!("a65d9851797832657860fedf5c570d18");
    let cipher = Speck128_128::new(&key.into());

    let mut block = plaintext.clone().into();
    cipher.encrypt_block(&mut block);

    assert_eq!(&ciphertext, block.as_slice());

    cipher.decrypt_block(&mut block);
    assert_eq!(&plaintext, block.as_slice());
}

#[test]
fn speck128_192() {
    let key = hex!("17161514131211100f0e0d0c0b0a09080706050403020100");
    let plaintext = hex!("726148206665696843206f7420746e65");
    let ciphertext = hex!("1be4cf3a13135566f9bc185de03c1886");
    let cipher = Speck128_192::new(&key.into());

    let mut block = plaintext.clone().into();
    cipher.encrypt_block(&mut block);

    assert_eq!(&ciphertext, block.as_slice());

    cipher.decrypt_block(&mut block);
    assert_eq!(&plaintext, block.as_slice());
}

#[test]
fn speck128_256() {
    let key = hex!("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");
    let plaintext = hex!("65736f6874206e49202e72656e6f6f70");
    let ciphertext = hex!("4109010405c0f53e4eeeb48d9c188f43");
    let cipher = Speck128_256::new(&key.into());

    let mut block = plaintext.clone().into();
    cipher.encrypt_block(&mut block);

    assert_eq!(&ciphertext, block.as_slice());

    cipher.decrypt_block(&mut block);
    assert_eq!(&plaintext, block.as_slice());
}
