#![no_std]
#[macro_use]
extern crate crypto_tests;
extern crate rc2;

use crypto_tests::block_cipher::{BlockCipherTest, encrypt_decrypt};

extern crate block_cipher_trait;

use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::BlockCipher;

#[test]
fn rc2() {
    let tests = new_block_cipher_tests!("1", "2", "3", "7");
    encrypt_decrypt::<rc2::RC2>(&tests);
}

#[test]
fn rc2_effective_key_64() {
    let tests = new_block_cipher_tests!("4", "5", "6");
    for test in &tests {
        let cipher = rc2::RC2::new_with_eff_key_len(test.key, 64);

        let mut buf = GenericArray::clone_from_slice(test.input);
        cipher.encrypt_block(&mut buf);
        assert_eq!(test.output, &buf[..]);

        let mut buf = GenericArray::clone_from_slice(test.output);
        cipher.decrypt_block(&mut buf);
        assert_eq!(test.input, &buf[..]);
    }
}

#[test]
fn rc2_effective_key_129() {
    let tests = new_block_cipher_tests!("8");
    for test in &tests {
        let cipher = rc2::RC2::new_with_eff_key_len(test.key, 129);

        let mut buf = GenericArray::clone_from_slice(test.input);
        cipher.encrypt_block(&mut buf);
        assert_eq!(test.output, &buf[..]);

        let mut buf = GenericArray::clone_from_slice(test.output);
        cipher.decrypt_block(&mut buf);
        assert_eq!(test.input, &buf[..]);
    }
}
