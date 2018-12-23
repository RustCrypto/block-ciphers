#![no_std]
extern crate block_cipher_trait;
extern crate magma;

use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::BlockCipher;

#[test]
fn magma_test() {
    let key = [
        255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242,
        241, 240, 0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204,
        221, 238, 255,
    ];
    let plaintext = [16, 50, 84, 118, 152, 186, 220, 254];
    let ciphertext = [61, 202, 216, 194, 229, 1, 233, 78];

    let state = magma::Magma::new_varkey(&key).unwrap();

    let mut block = GenericArray::clone_from_slice(&plaintext);
    state.encrypt_block(&mut block);
    assert_eq!(&ciphertext, block.as_slice());

    state.decrypt_block(&mut block);
    assert_eq!(&plaintext, block.as_slice());
}
