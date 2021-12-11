//! Test vectors are from NESSIE:
//! <https://www.cosic.esat.kuleuven.be/nessie/testvectors/>

cipher::block_cipher_test!(camellia128_test, "camellia128", camellia::Camellia128);
cipher::block_cipher_test!(camellia192_test, "camellia192", camellia::Camellia192);
cipher::block_cipher_test!(camellia256_test, "camellia256", camellia::Camellia256);
