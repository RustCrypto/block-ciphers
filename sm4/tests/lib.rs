//! Test vectors are from GM/T 0002-2012
#![no_std]

use block_cipher::{BlockCipher, NewBlockCipher};
use sm4::Sm4;

#[test]
fn sm4_example_1() {
    let key = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
        0x76, 0x54, 0x32, 0x10,
    ];
    let plaintext = key.clone(); // the same as key
    let ciphertext = [
        0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E, 0x86, 0xB3, 0xE9, 0x4F,
        0x53, 0x6E, 0x42, 0x46,
    ];

    let cipher = Sm4::new(&key.into());

    let mut block = plaintext.clone().into();
    cipher.encrypt_block(&mut block);

    assert_eq!(&ciphertext, block.as_slice());

    cipher.decrypt_block(&mut block);
    assert_eq!(&plaintext, block.as_slice());
}

#[test]
fn sm4_example_2() {
    let key = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
        0x76, 0x54, 0x32, 0x10,
    ];
    let plaintext = key.clone(); // the same as key
    let ciphertext = [
        0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f, 0x04, 0x02, 0xf8, 0x04,
        0xc3, 0x3d, 0x3f, 0x66,
    ];

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
