#![feature(test)]
extern crate test;

use cast5::Cast5;
use cipher::{block_decryptor_bench, block_encryptor_bench};

block_encryptor_bench!(Key: Cast5, cast5_encrypt_block, cast5_encrypt_blocks);
block_decryptor_bench!(Key: Cast5, cast5_decrypt_block, cast5_decrypt_blocks);
