//! Test vectors from Nessie:
//! http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-128-128.verified.test-vectors

cipher::block_cipher_test!(serpent128_test, "serpent128", serpent::Serpent);
cipher::block_cipher_test!(serpent192_test, "serpent192", serpent::Serpent);
cipher::block_cipher_test!(serpent256_test, "serpent256", serpent::Serpent);
