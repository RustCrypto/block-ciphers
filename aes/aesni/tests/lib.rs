//! Test vectors are from NESSIE:
//! https://www.cosic.esat.kuleuven.be/nessie/testvectors/

block_cipher::new_test!(aes128_test, "aes128", aesni::Aes128);
block_cipher::new_test!(aes192_test, "aes192", aesni::Aes192);
block_cipher::new_test!(aes256_test, "aes256", aesni::Aes256);
