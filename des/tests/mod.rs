//! Test vectors are from NESSIE:
//! https://www.cosic.esat.kuleuven.be/nessie/testvectors/

cipher::block_cipher_test!(des, des::Des);
cipher::block_cipher_test!(tdes, des::TdesEde3);
cipher::block_cipher_test!(tdes2, des::TdesEde2);
