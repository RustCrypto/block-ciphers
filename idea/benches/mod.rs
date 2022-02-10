#![feature(test)]
extern crate test;

use cipher::{block_decryptor_bench, block_encryptor_bench};
use idea::Idea;

block_encryptor_bench!(Key: Idea, idea_encrypt_block, idea_encrypt_blocks);
block_decryptor_bench!(Key: Idea, idea_decrypt_block, idea_decrypt_blocks);
