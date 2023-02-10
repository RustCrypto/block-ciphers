#![feature(test)]
extern crate test;

use camellia::{Camellia128, Camellia192, Camellia256};
use cipher::{block_decryptor_bench, block_encryptor_bench};

block_encryptor_bench!(
    Key: Camellia128,
    camellia128_encrypt_block,
    camellia128_encrypt_blocks
);
block_decryptor_bench!(
    Key: Camellia128,
    camellia128_decrypt_block,
    camellia128_decrypt_blocks
);

block_encryptor_bench!(
    Key: Camellia192,
    camellia192_encrypt_block,
    camellia192_encrypt_blocks
);
block_decryptor_bench!(
    Key: Camellia192,
    camellia192_decrypt_block,
    camellia192_decrypt_blocks
);

block_encryptor_bench!(
    Key: Camellia256,
    camellia256_encrypt_block,
    camellia256_encrypt_blocks
);
block_decryptor_bench!(
    Key: Camellia256,
    camellia256_decrypt_block,
    camellia256_decrypt_blocks
);
