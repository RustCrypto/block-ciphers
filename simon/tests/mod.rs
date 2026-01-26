//! Test vectors are from The Simon and Simon Families of Lightweight Block Ciphers (Appendix C)

use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use hex_literal::hex;
use simon_cipher::{
    Simon32_64, Simon48_72, Simon48_96, Simon64_96, Simon64_128, Simon96_96, Simon96_144,
    Simon128_128, Simon128_192, Simon128_256,
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
    simon32_64,
    Simon32_64,
    "1918111009080100",
    "65656877",
    "c69be9bb"
);

new_test!(
    simon48_72,
    Simon48_72,
    "1211100a0908020100",
    "6120676e696c",
    "dae5ac292cac"
);

new_test!(
    simon48_96,
    Simon48_96,
    "1a19181211100a0908020100",
    "72696320646e",
    "6e06a5acf156"
);

new_test!(
    simon64_96,
    Simon64_96,
    "131211100b0a090803020100",
    "6f7220676e696c63",
    "5ca2e27f111a8fc8"
);

new_test!(
    simon64_128,
    Simon64_128,
    "1b1a1918131211100b0a090803020100",
    "656b696c20646e75",
    "44c8fc20b9dfa07a"
);

new_test!(
    simon96_96,
    Simon96_96,
    "0d0c0b0a0908050403020100",
    "2072616c6c69702065687420",
    "602807a462b469063d8ff082"
);

new_test!(
    simon96_144,
    Simon96_144,
    "1514131211100d0c0b0a0908050403020100",
    "74616874207473756420666f",
    "ecad1c6c451e3f59c5db1ae9"
);

new_test!(
    simon128_128,
    Simon128_128,
    "0f0e0d0c0b0a09080706050403020100",
    "63736564207372656c6c657661727420",
    "49681b1e1e54fe3f65aa832af84e0bbc"
);

new_test!(
    simon128_192,
    Simon128_192,
    "17161514131211100f0e0d0c0b0a09080706050403020100",
    "206572656874206e6568772065626972",
    "c4ac61effcdc0d4f6c9c8d6e2597b85b"
);

new_test!(
    simon128_256,
    Simon128_256,
    "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
    "74206e69206d6f6f6d69732061207369",
    "8d2b5579afc8a3a03bf72a87efe7b868"
);
