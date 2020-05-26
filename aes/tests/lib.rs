//! Test vectors are from NESSIE:
//! https://www.cosic.esat.kuleuven.be/nessie/testvectors/
#![no_std]
use aes;
#[macro_use]
extern crate block_cipher;

new_test!(aes128_test, "aes128", aes::Aes128);
new_test!(aes192_test, "aes192", aes::Aes192);
new_test!(aes256_test, "aes256", aes::Aes256);
