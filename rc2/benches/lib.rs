#![no_std]
#![feature(test)]
#[macro_use]
extern crate crypto_tests;
extern crate rc2;

bench_block_cipher!(rc2::RC2, 16);
