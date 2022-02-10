#![feature(test)]
extern crate test;

use blowfish::Blowfish;
use cipher::{block_decryptor_bench, block_encryptor_bench};

block_encryptor_bench!(
    Key: Blowfish,
    blowfish_encrypt_block,
    blowfish_encrypt_blocks,
);
block_decryptor_bench!(
    Key: Blowfish,
    blowfish_decrypt_block,
    blowfish_decrypt_blocks,
);
