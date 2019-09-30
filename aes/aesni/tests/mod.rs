//! Test vectors are from NESSIE:
//! https://www.cosic.esat.kuleuven.be/nessie/testvectors/
#![no_std]
#![cfg(any(target_arch = "x86_64", target_arch = "x86"))]
use block_cipher_trait::new_test;

new_test!(aes128_test, "aes128", aesni::Aes128);
new_test!(aes192_test, "aes192", aesni::Aes192);
new_test!(aes256_test, "aes256", aesni::Aes256);
