#![feature(test)]
extern crate test;

use cipher::{block_decryptor_bench, block_encryptor_bench};
use xtea::Xtea;

block_encryptor_bench!(Key: Xtea, xtea_encrypt_block, xtea_encrypt_blocks);
block_decryptor_bench!(Key: Xtea, xtea_decrypt_block, xtea_decrypt_blocks);
