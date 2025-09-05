//! Test vectors are from NESSIE:
//! https://www.cosic.esat.kuleuven.be/nessie/testvectors/

cipher::block_cipher_test!(aes128, aes::Aes128);
cipher::block_cipher_test!(aes192, aes::Aes192);
cipher::block_cipher_test!(aes256, aes::Aes256);

cipher::block_cipher_test!(aes128_enc, "aes128", aes::Aes128Enc, encrypt_test);
cipher::block_cipher_test!(aes192_enc, "aes192", aes::Aes192Enc, encrypt_test);
cipher::block_cipher_test!(aes256_enc, "aes256", aes::Aes256Enc, encrypt_test);

cipher::block_cipher_test!(aes128_dec, "aes128", aes::Aes128Dec, decrypt_test);
cipher::block_cipher_test!(aes192_dec, "aes192", aes::Aes192Dec, decrypt_test);
cipher::block_cipher_test!(aes256_dec, "aes256", aes::Aes256Dec, decrypt_test);
