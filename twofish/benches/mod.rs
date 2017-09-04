#![no_std]
#![feature(test)]
#[macro_use]
extern crate crypto_tests;
extern crate twofish;

bench_block_cipher!(twofish::Twofish, 16);
