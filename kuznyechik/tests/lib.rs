#![cfg_attr(rustfmt, rustfmt_skip)]

use cipher::{generic_array::GenericArray, BlockEncrypt, BlockDecrypt, NewBlockCipher};
use hex_literal::hex;

/// Example vectors from GOST 34.12-2018
#[test]
fn kuznyechik() {
    let key = hex!("
        8899AABBCCDDEEFF0011223344556677
        FEDCBA98765432100123456789ABCDEF
    ");
    let plaintext = hex!("1122334455667700FFEEDDCCBBAA9988");
    let ciphertext = hex!("7F679D90BEBC24305a468d42b9d4EDCD");

    let state = kuznyechik::Kuznyechik::new_from_slice(&key).unwrap();

    let mut block = GenericArray::clone_from_slice(&plaintext);
    state.encrypt_block(&mut block);
    assert_eq!(&ciphertext, block.as_slice());

    state.decrypt_block(&mut block);
    assert_eq!(&plaintext, block.as_slice());
}
