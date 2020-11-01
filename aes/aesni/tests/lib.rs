//! Test vectors are from NESSIE:
//! https://www.cosic.esat.kuleuven.be/nessie/testvectors/

cipher::block_cipher_test!(aes128_test, "aes128", aesni::Aes128);
cipher::block_cipher_test!(aes192_test, "aes192", aesni::Aes192);
cipher::block_cipher_test!(aes256_test, "aes256", aesni::Aes256);
