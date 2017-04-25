#![no_std]
#[macro_use]
extern crate crypto_tests;
extern crate rc2;

mod test_vectors;

use crypto_tests::block_cipher::{BlockCipherTest, encrypt_decrypt};

extern crate block_cipher_trait;
extern crate generic_array;

use block_cipher_trait::from_slice;
use generic_array::GenericArray;
use block_cipher_trait::BlockCipher;

#[test]
fn rc2() {
    let tests = new_block_cipher_tests!("1", "2", "3", "4");
    encrypt_decrypt::<rc2::RC2>(&tests);
}

#[test]
fn rc2_with_different_effective_key_length() {
    let mut buf = GenericArray::new();

    for test in test_vectors::RC2_EFF_KEY_LEN_TESTS {
        let cipher = rc2::RC2::new_with_effective_key_length(test.key, test.eff_key_length);

        cipher.encrypt_block(&from_slice(test.input), &mut buf);
        assert_eq!(test.output, &buf[..]);
        cipher.decrypt_block(&from_slice(test.output), &mut buf);
        assert_eq!(test.input, &buf[..]);
    }
}
