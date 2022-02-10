#![feature(test)]
extern crate test;

use cipher::{block_decryptor_bench, block_encryptor_bench};
use magma::Magma;

block_encryptor_bench!(Key: Magma, magma_encrypt_block, magma_encrypt_blocks);
block_decryptor_bench!(Key: Magma, magma_decrypt_block, magma_decrypt_blocks);
