#![feature(test)]
extern crate test;

use aria::{Aria128, Aria192, Aria256};
use cipher::{block_decryptor_bench, block_encryptor_bench};

block_encryptor_bench!(Key: Aria128, aria128_encrypt_block, aria128_encrypt_blocks);
block_decryptor_bench!(Key: Aria128, aria128_decrypt_block, aria128_decrypt_blocks);

block_encryptor_bench!(Key: Aria192, aria192_encrypt_block, aria192_encrypt_blocks);
block_decryptor_bench!(Key: Aria192, aria192_decrypt_block, aria192_decrypt_blocks);

block_encryptor_bench!(Key: Aria256, aria256_encrypt_block, aria256_encrypt_blocks);
block_decryptor_bench!(Key: Aria256, aria256_decrypt_block, aria256_decrypt_blocks);
