//! Test vectors are from NESSIE:
//! https://www.cosic.esat.kuleuven.be/nessie/testvectors/
#![no_std]

use block_cipher::new_test;

new_test!(aes128_test, "aes128", aes_soft::Aes128);
new_test!(aes192_test, "aes192", aes_soft::Aes192);
new_test!(aes256_test, "aes256", aes_soft::Aes256);
