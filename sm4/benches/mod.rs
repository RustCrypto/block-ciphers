#![feature(test)]
extern crate test;

use cipher::{block_decryptor_bench, block_encryptor_bench};
use sm4::Sm4;

block_encryptor_bench!(Key: Sm4, sm4_encrypt_block, sm4_encrypt_blocks);
block_decryptor_bench!(Key: Sm4, sm4_decrypt_block, sm4_decrypt_blocks);
