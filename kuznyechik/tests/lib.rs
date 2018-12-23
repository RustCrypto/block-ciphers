#![no_std]
extern crate block_cipher_trait;
extern crate kuznyechik;

use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::BlockCipher;

#[test]
fn kuznyechik() {
    let key = [
        239, 205, 171, 137, 103, 69, 35, 1, 16, 50, 84, 118, 152, 186, 220,
        254, 119, 102, 85, 68, 51, 34, 17, 0, 255, 238, 221, 204, 187, 170,
        153, 136,
    ];
    let plaintext = [
        136, 153, 170, 187, 204, 221, 238, 255, 0, 119, 102, 85, 68, 51, 34, 17
    ];
    let ciphertext = [
        205, 237, 212, 185, 66, 141, 70, 90, 48, 36, 188, 190, 144, 157, 103,
        127,
    ];

    let state = kuznyechik::Kuznyechik::new_varkey(&key).unwrap();

    let mut block = GenericArray::clone_from_slice(&plaintext);
    state.encrypt_block(&mut block);
    assert_eq!(&ciphertext, block.as_slice());

    state.decrypt_block(&mut block);
    assert_eq!(&plaintext, block.as_slice());
}
