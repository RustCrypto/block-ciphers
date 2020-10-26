//! Test vectors are from NESSIE:
//! https://www.cosic.esat.kuleuven.be/nessie/testvectors/

cipher::new_test!(aes128_test, "aes128", aes_soft::Aes128);
cipher::new_test!(aes192_test, "aes192", aes_soft::Aes192);
cipher::new_test!(aes256_test, "aes256", aes_soft::Aes256);

macro_rules! new_encrypt_only_test {
    ($name:ident, $test_name:expr, $cipher:ty) => {
        #[test]
        fn $name() {
            use cipher::block::{dev::blobby::Blob3Iterator, BlockCipher, NewBlockCipher};
            use cipher::generic_array::{typenum::Unsigned, GenericArray};

            fn run_test(key: &[u8], pt: &[u8], ct: &[u8]) -> bool {
                let state = <$cipher as NewBlockCipher>::new_varkey(key).unwrap();

                let mut block = GenericArray::clone_from_slice(pt);
                state.encrypt_block(&mut block);
                if ct != block.as_slice() {
                    return false;
                }

                true
            }

            fn run_par_test(key: &[u8], pt: &[u8]) -> bool {
                type ParBlocks = <$cipher as BlockCipher>::ParBlocks;
                type BlockSize = <$cipher as BlockCipher>::BlockSize;
                type Block = GenericArray<u8, BlockSize>;
                type ParBlock = GenericArray<Block, ParBlocks>;

                let state = <$cipher as NewBlockCipher>::new_varkey(key).unwrap();

                let block = Block::clone_from_slice(pt);
                let mut blocks1 = ParBlock::default();
                for (i, b) in blocks1.iter_mut().enumerate() {
                    *b = block;
                    b[0] = b[0].wrapping_add(i as u8);
                }
                let mut blocks2 = blocks1.clone();

                // check that `encrypt_blocks` and `encrypt_block`
                // result in the same ciphertext
                state.encrypt_blocks(&mut blocks1);
                for b in blocks2.iter_mut() {
                    state.encrypt_block(b);
                }
                if blocks1 != blocks2 {
                    return false;
                }

                true
            }

            let pb = <$cipher as BlockCipher>::ParBlocks::to_usize();
            let data = include_bytes!(concat!("data/", $test_name, ".blb"));
            for (i, row) in Blob3Iterator::new(data).unwrap().enumerate() {
                let [key, pt, ct] = row.unwrap();
                if !run_test(key, pt, ct) {
                    panic!(
                        "\n\
                         Failed test №{}\n\
                         key:\t{:?}\n\
                         plaintext:\t{:?}\n\
                         ciphertext:\t{:?}\n",
                        i, key, pt, ct,
                    );
                }

                // test parallel blocks encryption/decryption
                if pb != 1 {
                    if !run_par_test(key, pt) {
                        panic!(
                            "\n\
                             Failed parallel test №{}\n\
                             key:\t{:?}\n\
                             plaintext:\t{:?}\n\
                             ciphertext:\t{:?}\n",
                            i, key, pt, ct,
                        );
                    }
                }
            }
            // test if cipher can be cloned
            let key = Default::default();
            let _ = <$cipher as NewBlockCipher>::new(&key).clone();
        }
    };
}

new_encrypt_only_test!(aes128_fixsliced_test, "aes128", aes_soft::Aes128Fixsliced);
new_encrypt_only_test!(aes192_fixsliced_test, "aes192", aes_soft::Aes192Fixsliced);
new_encrypt_only_test!(aes256_fixsliced_test, "aes256", aes_soft::Aes256Fixsliced);
