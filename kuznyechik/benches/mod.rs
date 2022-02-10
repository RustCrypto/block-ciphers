#![feature(test)]
extern crate test;

use cipher::{block_decryptor_bench, block_encryptor_bench};
use kuznyechik::Kuznyechik;

block_encryptor_bench!(
    Key: Kuznyechik,
    kuznyechik_encrypt_block,
    kuznyechik_encrypt_blocks,
);
block_decryptor_bench!(
    Key: Kuznyechik,
    kuznyechik_decrypt_block,
    kuznyechik_decrypt_blocks,
);
