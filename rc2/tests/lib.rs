#![no_std]
#[macro_use]
extern crate crypto_tests;
extern crate rc2;

use crypto_tests::block_cipher::{BlockCipherTest, encrypt_decrypt};

#[test]
fn rc2() {
    let tests = new_block_cipher_tests!("1", "2");
    encrypt_decrypt::<rc2::RC2>(&tests);
}
