#![feature(test)]
extern crate test;

use cipher::{block_decryptor_bench, block_encryptor_bench};
use belt_block::BeltBlock;

block_encryptor_bench!(
    Key: BeltBlock,
    beltblock_encrypt_block,
    beltblock_encrypt_blocks,
);
block_decryptor_bench!(
    Key: BeltBlock,
    beltblock_decrypt_block,
    beltblock_decrypt_blocks,
);