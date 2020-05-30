#![no_std]

use block_cipher::generic_array::GenericArray;
use idea::{BlockCipher, Idea, NewBlockCipher};

mod data;

macro_rules! idea_test {
    ($func:ident, $test_vector:expr) => {
        #[test]
        fn $func() {
            let user_key = GenericArray::from_slice(&$test_vector.key);
            let cipher = Idea::new(&user_key);

            let mut block = GenericArray::clone_from_slice(&$test_vector.plain_text);
            cipher.encrypt_block(&mut block);
            assert_eq!(&block[..], &$test_vector.cipher_text[..]);

            cipher.decrypt_block(&mut block);
            assert_eq!(&block[..], &$test_vector.plain_text[..]);
        }
    };
}

idea_test!(idea_test_1, &data::TEST_VECTOR_1);
idea_test!(idea_test_2, &data::TEST_VECTOR_2);
idea_test!(idea_test_3, &data::TEST_VECTOR_3);
idea_test!(idea_test_4, &data::TEST_VECTOR_4);
idea_test!(idea_test_5, &data::TEST_VECTOR_5);
idea_test!(idea_test_6, &data::TEST_VECTOR_6);
idea_test!(idea_test_7, &data::TEST_VECTOR_7);
idea_test!(idea_test_8, &data::TEST_VECTOR_8);
