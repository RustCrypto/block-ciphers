// TODO(tarcieri): update tests to support RustCrypto/traits#1916
cipher::block_cipher_test!(blowfish, blowfish::Blowfish);
// Tests for BlowfishLE were randomly generated using implementation in this crate
cipher::block_cipher_test!(blowfish_le, blowfish::BlowfishLE);
