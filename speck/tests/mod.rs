//! Test vectors are from The Simon and Speck Families of Lightweight Block Ciphers (Appendix C)

use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use hex_literal::hex;
use speck_cipher::{
    Speck32_64, Speck48_72, Speck48_96, Speck64_96, Speck64_128, Speck96_96, Speck96_144,
    Speck128_128, Speck128_192, Speck128_256,
};

macro_rules! new_test {
    (
        $name:ident,
        $cipher:ident,
        $key_hex:expr,
        $pt_hex:expr,
        $ct_hex:expr
    ) => {
        #[test]
        fn $name() {
            let key = hex!($key_hex);
            let plaintext = hex!($pt_hex);
            let ciphertext = hex!($ct_hex);
            let cipher = $cipher::new(&key.into());

            let mut block = plaintext.clone().into();
            cipher.encrypt_block(&mut block);

            assert_eq!(&ciphertext, block.as_slice());

            cipher.decrypt_block(&mut block);
            assert_eq!(&plaintext, block.as_slice());
        }
    };
}

new_test!(
    speck32_64,
    Speck32_64,
    "1918111009080100",
    "6574694c",
    "a86842f2"
);

new_test!(
    speck48_72,
    Speck48_72,
    "1211100a0908020100",
    "20796c6c6172",
    "c049a5385adc"
);

new_test!(
    speck48_96,
    Speck48_96,
    "1a19181211100a0908020100",
    "6d2073696874",
    "735e10b6445d"
);

new_test!(
    speck64_96,
    Speck64_96,
    "131211100b0a090803020100",
    "74614620736e6165",
    "9f7952ec4175946c"
);

new_test!(
    speck64_128,
    Speck64_128,
    "1b1a1918131211100b0a090803020100",
    "3b7265747475432d",
    "8c6fa548454e028b"
);

new_test!(
    speck96_96,
    Speck96_96,
    "0d0c0b0a0908050403020100",
    "65776f68202c656761737520",
    "9e4d09ab717862bdde8f79aa"
);

new_test!(
    speck96_144,
    Speck96_144,
    "1514131211100d0c0b0a0908050403020100",
    "656d6974206e69202c726576",
    "2bf31072228a7ae440252ee6"
);

new_test!(
    speck128_128,
    Speck128_128,
    "0f0e0d0c0b0a09080706050403020100",
    "6c617669757165207469206564616d20",
    "a65d9851797832657860fedf5c570d18"
);

new_test!(
    speck128_192,
    Speck128_192,
    "17161514131211100f0e0d0c0b0a09080706050403020100",
    "726148206665696843206f7420746e65",
    "1be4cf3a13135566f9bc185de03c1886"
);

new_test!(
    speck128_256,
    Speck128_256,
    "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
    "65736f6874206e49202e72656e6f6f70",
    "4109010405c0f53e4eeeb48d9c188f43"
);
