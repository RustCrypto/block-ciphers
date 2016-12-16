#![no_std]
#![feature(test)]
#[macro_use]
extern crate crypto_tests;
extern crate blowfish;

bench_block_cipher!(blowfish::Blowfish, &[0u8; 16], &[1u8; 8]);
