#![feature(test)]
extern crate test;

macro_rules! benches {
    ($name:ident, $cipher:ty) => {
        mod $name {
            use cipher::{Key, KeyInit, block_decryptor_bench, block_encryptor_bench};

            block_encryptor_bench!(Key: $cipher, encrypt_block, encrypt_blocks);
            block_decryptor_bench!(Key: $cipher, decrypt_block, decrypt_blocks);

            #[bench]
            fn key_init(bh: &mut test::Bencher) {
                let key = Key::<$cipher>::default();
                bh.iter(|| <$cipher>::new(test::black_box(&key)));
            }
        }
    };
}

benches!(des, ::des::Des);
benches!(tdes_ede2, ::des::TdesEde2);
benches!(tdes_ede3, ::des::TdesEde3);
benches!(tdes_eee2, ::des::TdesEee2);
benches!(tdes_eee3, ::des::TdesEee3);
