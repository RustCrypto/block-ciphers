#![feature(test)]
extern crate test;

use cipher::{block_decryptor_bench, block_encryptor_bench};
use serpent::Serpent;

block_encryptor_bench!(Key: Serpent, serpent_encrypt_block, serpent_encrypt_blocks);
block_decryptor_bench!(Key: Serpent, serpent_decrypt_block, serpent_decrypt_blocks);
