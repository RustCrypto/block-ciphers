#![no_std]
#![feature(test)]
#[macro_use]
extern crate crypto_tests;
extern crate kuznyechik;

bench_block_cipher!(kuznyechik::Kuznyechik, 32);
