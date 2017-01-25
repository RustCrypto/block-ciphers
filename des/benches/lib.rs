#![no_std]
#![feature(test)]

#[macro_use]
extern crate crypto_tests;
extern crate des;

bench_block_cipher!(des::Des, &[0u8; 8], &[0u8; 8]);
