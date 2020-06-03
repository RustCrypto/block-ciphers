#![no_std]
#![cfg_attr(rustfmt, rustfmt_skip)]

use block_cipher::generic_array::GenericArray;
use block_cipher::{BlockCipher, NewBlockCipher};

/// Example vectors from GOST 34.12-2018
#[test]
fn kuznyechik() {
    let key = [
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    ];
    let plaintext = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
    ];
    let ciphertext = [
        0x7F, 0x67, 0x9D, 0x90, 0xBE, 0xBC, 0x24, 0x30,
        0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xED, 0xCD,
    ];

    let state = kuznyechik::Kuznyechik::new_varkey(&key).unwrap();

    let mut block = GenericArray::clone_from_slice(&plaintext);
    state.encrypt_block(&mut block);
    assert_eq!(&ciphertext, block.as_slice());

    state.decrypt_block(&mut block);
    assert_eq!(&plaintext, block.as_slice());
}
