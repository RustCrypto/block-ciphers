//! Test vectors are from NESSIE:
//! https://www.cosic.esat.kuleuven.be/nessie/testvectors/

block_cipher::new_test!(aes128_test, "aes128", aes_soft::Aes128);
block_cipher::new_test!(aes192_test, "aes192", aes_soft::Aes192);
block_cipher::new_test!(aes256_test, "aes256", aes_soft::Aes256);
