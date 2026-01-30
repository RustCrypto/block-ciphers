use new::{enc, dec};
use hex_literal::hex;

const KEYS: [[u8; 16]; 4] = [
    hex!("00112233445566778899aabbccddeeff"),
    hex!("ffeeddccbbaa99887766554433221100"),
    hex!("000102030405060708090a0b0c0d0e0f"),
    hex!("28dbc3bc49ffd87dcfa509b11d422be7"),
];

const PTEXTS: [[u8; 8]; 4] = [
    hex!("0000000000000000"),
    hex!("0011223344556677"),
    hex!("0123456789abcdef"),
    hex!("b41e6be2eba84a14"),
];

const CTEXTS: [[u8; 8]; 4] = [
    hex!("f2034fd9ae18f400"),
    hex!("d8e643e5729fce23"),
    hex!("66f4238da2b26f7a"),
    hex!("c61f9c20757a04cc"),
];

#[test]
fn test_vectors() {
    for i in 0..KEYS.len() {
        let ciphertext = enc::encrypt(&PTEXTS[i], &KEYS[i]);

        assert_eq!(ciphertext, CTEXTS[i], "Encryption failed at test vector {}", i);
      
        let decrypted = dec::decrypt(&ciphertext, &KEYS[i]);

        assert_eq!(decrypted, PTEXTS[i], "Decryption failed at test vector {}", i);
    }
}
