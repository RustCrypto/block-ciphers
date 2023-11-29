//! Test vectors are from GM/T 0002-2012

use cipher::{Block, BlockDecrypt, BlockEncrypt, KeyInit};
use hex_literal::hex;
use sm4::Sm4;

#[test]
fn sm4_example_1() {
    let key = hex!("0123456789abcdeffedcba9876543210");
    let plaintext = key;
    let ciphertext = hex!("681EDF34D206965E86B3E94F536E4246");
    let cipher = Sm4::new(&key.into());

    let mut block = plaintext.into();
    cipher.encrypt_block(&mut block);

    assert_eq!(&ciphertext, block.as_slice());

    cipher.decrypt_block(&mut block);
    assert_eq!(&plaintext, block.as_slice());
}

#[test]
fn sm4_example_2() {
    let key = hex!("0123456789abcdeffedcba9876543210");
    let plaintext = key;
    let ciphertext = hex!("595298c7c6fd271f0402f804c33d3f66");

    let cipher = Sm4::new(&key.into());

    let mut block = plaintext.into();
    for _ in 0..1_000_000 {
        cipher.encrypt_block(&mut block);
    }
    assert_eq!(&ciphertext, block.as_slice());

    for _ in 0..1_000_000 {
        cipher.decrypt_block(&mut block);
    }
    assert_eq!(&plaintext, block.as_slice());
}

#[test]
fn sm4_example_1_blocks() {
    let key = hex!("0123456789abcdeffedcba9876543210");
    let plaintext: [Block<Sm4>; 15] = [
        key.into(),
        key.into(),
        key.into(),
        key.into(),
        key.into(),
        key.into(),
        key.into(),
        key.into(),
        key.into(),
        key.into(),
        key.into(),
        key.into(),
        key.into(),
        key.into(),
        key.into(),
    ];
    let ciphertext_b = hex!("681EDF34D206965E86B3E94F536E4246");
    let ciphertext: [Block<Sm4>; 15] = [
        ciphertext_b.into(),
        ciphertext_b.into(),
        ciphertext_b.into(),
        ciphertext_b.into(),
        ciphertext_b.into(),
        ciphertext_b.into(),
        ciphertext_b.into(),
        ciphertext_b.into(),
        ciphertext_b.into(),
        ciphertext_b.into(),
        ciphertext_b.into(),
        ciphertext_b.into(),
        ciphertext_b.into(),
        ciphertext_b.into(),
        ciphertext_b.into(),
    ];
    let cipher = Sm4::new(&key.into());

    let mut blocks = plaintext;
    cipher.encrypt_blocks(&mut blocks);

    assert_eq!(&ciphertext, &blocks);

    cipher.decrypt_blocks(&mut blocks);
    assert_eq!(&plaintext, &blocks);
}
