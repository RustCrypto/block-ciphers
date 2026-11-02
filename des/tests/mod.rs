//! Test vectors are from NESSIE:
//! https://www.cosic.esat.kuleuven.be/nessie/testvectors/

cipher::block_cipher_test!(des, des::Des);
cipher::block_cipher_test!(tdes, des::TdesEde3);
cipher::block_cipher_test!(tdes2, des::TdesEde2);

use cipher::dev::block_cipher::{TestVector, encrypt_decrypt_test};
use hex_literal::hex;

// Cross-checked with three successive OpenSSL DES-ECB encryptions.
#[test]
fn tdes_eee2() {
    let tv = TestVector {
        key: &hex!("133457799bbcdff10e329232ea6d0d73"),
        plaintext: &hex!("0123456789abcdef"),
        ciphertext: &hex!("bbf248468b8878ac"),
    };
    encrypt_decrypt_test::<des::TdesEee2>(&tv).unwrap();
}

// Cross-checked with three successive OpenSSL DES-ECB encryptions.
#[test]
fn tdes_eee3() {
    let tv = TestVector {
        key: &hex!("133457799bbcdff10e329232ea6d0d73aabb09182736ccdd"),
        plaintext: &hex!("0123456789abcdef"),
        ciphertext: &hex!("afc8f360c3c7d674"),
    };
    encrypt_decrypt_test::<des::TdesEee3>(&tv).unwrap();
}
