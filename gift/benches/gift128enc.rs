#![feature(test)]
extern crate test;

use cipher::{KeyInit, block_decryptor_bench, block_encryptor_bench};
use gift_cipher::Gift128;

block_encryptor_bench!(
    Key: Gift128,
    gift128_encrypt_block,
    gift128_encrypt_blocks,
);
block_decryptor_bench!(
    Key: Gift128,
    gift128_decrypt_block,
    gift128_decrypt_blocks,
);

#[bench]
fn gift128_new(bh: &mut test::Bencher) {
    bh.iter(|| {
        let key = test::black_box(Default::default());
        let cipher = Gift128::new(&key);
        test::black_box(&cipher);
    });
}
