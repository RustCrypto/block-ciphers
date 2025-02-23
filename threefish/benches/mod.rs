#![feature(test)]
extern crate test;

use cipher::{block_decryptor_bench, block_encryptor_bench};
use threefish::{Threefish256, Threefish512, Threefish1024};

block_encryptor_bench!(
    Key: Threefish256,
    threefish256_encrypt_block,
    threefish256_encrypt_blocks,
);
block_decryptor_bench!(
    Key: Threefish256,
    threefish256_decrypt_block,
    threefish256_decrypt_blocks,
);

block_encryptor_bench!(
    Key: Threefish512,
    threefish512_encrypt_block,
    threefish512_encrypt_blocks,
);
block_decryptor_bench!(
    Key: Threefish512,
    threefish512_decrypt_block,
    threefish512_decrypt_blocks,
);

block_encryptor_bench!(
    Key: Threefish1024,
    threefish1024_encrypt_block,
    threefish1024_encrypt_blocks,
);
block_decryptor_bench!(
    Key: Threefish1024,
    threefish1024_decrypt_block,
    threefish1024_decrypt_blocks,
);
