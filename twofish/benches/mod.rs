#![feature(test)]
extern crate test;

use cipher::{block_decryptor_bench, block_encryptor_bench};
use twofish::Twofish;

block_encryptor_bench!(Key: Twofish, twofish_encrypt_block, twofish_encrypt_blocks);
block_decryptor_bench!(Key: Twofish, twofish_decrypt_block, twofish_decrypt_blocks);
