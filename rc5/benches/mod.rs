#![feature(test)]
extern crate test;

use cipher::{block_decryptor_bench, block_encryptor_bench};
use rc5::RC5_32_20_16;

block_encryptor_bench!(Key: RC5_32_20_16, rc5_encrypt_block, rc5_encrypt_blocks,);
block_decryptor_bench!(Key: RC5_32_20_16, rc5_decrypt_block, rc5_decrypt_blocks,);
