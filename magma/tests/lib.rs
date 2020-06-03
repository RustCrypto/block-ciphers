#![no_std]
use magma;

use block_cipher::generic_array::GenericArray;
use block_cipher::{BlockCipher, NewBlockCipher};

/// Example vectors from GOST 34.12-2018
#[test]
fn magma_test() {
    let key = [
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
        0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
    ];
    let plaintext = [
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    ];
    let ciphertext = [
        0x4E, 0xE9, 0x01, 0xE5, 0xC2, 0xD8, 0xCA, 0x3D,
    ];

    let state = magma::Magma::new_varkey(&key).unwrap();

    let mut block = GenericArray::clone_from_slice(&plaintext);
    state.encrypt_block(&mut block);
    assert_eq!(&ciphertext, block.as_slice());

    state.decrypt_block(&mut block);
    assert_eq!(&plaintext, block.as_slice());
}

/*
// an attempt to test with vectors from
// https://github.com/gost-engine/engine/blob/master/test/03-encrypt.t
#[test]
fn engine_test() {
    use block_modes::{BlockMode, Cbc, block_padding::Pkcs7};

    type Cipher = Cbc<magma::Gost89CryptoProA, Pkcs7>;

    let key: [u8; 32] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    ];
    let iv: [u8; 8] = [0; 8];
    let plaintext = b"The quick brown fox jumps over the lazy dog\n";

    let c = Cipher::new_var(&key, &iv).unwrap();
    let ct = c.encrypt_vec(plaintext);
    for b in ct {
        print!("0x{:02X}, ", b);
    }
    println!();
}
*/
