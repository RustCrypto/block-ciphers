#![feature(test)]
extern crate test;

use cipher::consts::*;
use cipher::{block_decryptor_bench, block_encryptor_bench};
use rc5::RC5;

block_encryptor_bench!(
    Key: RC5<u32, U12, U16>,
    rc5_32_12_16_encrypt_block,
    rc5_32_12_16_encrypt_blocks,
);
block_decryptor_bench!(
    Key: RC5<u32, U12, U16>,
    rc5_32_12_16_decrypt_block,
    rc5_32_12_16_decrypt_blocks,
);

block_encryptor_bench!(
    Key: RC5<u32, U16, U16>,
    rc5_32_16_16_encrypt_block,
    rc5_32_16_16_encrypt_blocks,
);
block_decryptor_bench!(
    Key: RC5<u32, U16, U16>,
    rc5_32_16_16_decrypt_block,
    rc5_32_16_16_decrypt_blocks,
);
