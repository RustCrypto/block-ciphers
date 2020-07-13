use magma;
use block_cipher::generic_array::GenericArray;
use block_cipher::{BlockCipher, NewBlockCipher};
use hex_literal::hex;

/// Example vectors from GOST 34.12-2018
#[test]
#[rustfmt::skip]
fn magma_test() {
    let key = hex!("
        FFEEDDCCBBAA99887766554433221100
        F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF
    ");
    let plaintext = hex!("FEDCBA9876543210");
    let ciphertext = hex!("4EE901E5C2D8CA3D");

    let state = magma::Magma::new_varkey(&key).unwrap();

    let mut block = GenericArray::clone_from_slice(&plaintext);
    state.encrypt_block(&mut block);
    assert_eq!(&ciphertext, block.as_slice());

    state.decrypt_block(&mut block);
    assert_eq!(&plaintext, block.as_slice());
}
