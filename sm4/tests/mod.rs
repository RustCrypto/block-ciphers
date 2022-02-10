//! Test vectors are from GM/T 0002-2012

use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use hex_literal::hex;
use sm4::Sm4;

#[test]
fn sm4_example_1() {
    let key = hex!("0123456789abcdeffedcba9876543210");
    let plaintext = key.clone();
    let ciphertext = hex!("681EDF34D206965E86B3E94F536E4246");
    let cipher = Sm4::new(&key.into());

    let mut block = plaintext.clone().into();
    cipher.encrypt_block(&mut block);

    assert_eq!(&ciphertext, block.as_slice());

    cipher.decrypt_block(&mut block);
    assert_eq!(&plaintext, block.as_slice());
}

#[test]
fn sm4_example_2() {
    let key = hex!("0123456789abcdeffedcba9876543210");
    let plaintext = key.clone();
    let ciphertext = hex!("595298c7c6fd271f0402f804c33d3f66");

    let cipher = Sm4::new(&key.into());

    let mut block = plaintext.clone().into();
    for _ in 0..1_000_000 {
        cipher.encrypt_block(&mut block);
    }
    assert_eq!(&ciphertext, block.as_slice());

    for _ in 0..1_000_000 {
        cipher.decrypt_block(&mut block);
    }
    assert_eq!(&plaintext, block.as_slice());
}
