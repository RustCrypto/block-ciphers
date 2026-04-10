use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit, array::Array};
use gift_cipher::Gift128;
use hex_literal::hex;

const KEYS: [[u8; 16]; 3] = [
    hex!("00000000000000000000000000000000"),
    hex!("fedcba9876543210fedcba9876543210"),
    hex!("d0f5c59a7700d3e799028fa9f90ad837"),
];

const PTEXT: [[u8; 16]; 3] = [
    hex!("00000000000000000000000000000000"),
    hex!("fedcba9876543210fedcba9876543210"),
    hex!("e39c141fa57dba43f08a85b6a91f86c1"),
];

const CTEXT: [[u8; 16]; 3] = [
    hex!("cd0bd738388ad3f668b15a36ceb6ff92"),
    hex!("8422241a6dbf5a9346af468409ee0152"),
    hex!("13ede67cbdcc3dbf400a62d6977265ea"),
];

#[test]
fn test_vectors() {
    for i in 0..3 {
        let cipher = Gift128::new(&KEYS[i].into());
        let mut buf = Array::from(PTEXT[i]);

        cipher.encrypt_block(&mut buf);
        assert_eq!(buf, CTEXT[i]);

        cipher.decrypt_block(&mut buf);
        assert_eq!(buf, PTEXT[i]);
    }
}
