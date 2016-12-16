#![no_std]
#[macro_use]
extern crate crypto_tests;
extern crate blowfish;

use crypto_tests::block_cipher::{BlockCipherTest, encrypt_decrypt};

#[test]
fn blowfish() {
    let tests = new_block_cipher_tests!(
        "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13",
        "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25",
        "26", "27", "28", "29", "30", "31", "32", "33", "34");
    encrypt_decrypt::<blowfish::Blowfish>(&tests);
}
