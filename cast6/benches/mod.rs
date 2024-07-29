#![feature(test)]
extern crate test;

use cast6::Cast6;
use cipher::{block_decryptor_bench, block_encryptor_bench};

block_encryptor_bench!(Key: Cast6, cast6_encrypt_block, cast6_encrypt_blocks);
block_decryptor_bench!(Key: Cast6, cast6_decrypt_block, cast6_decrypt_blocks);
