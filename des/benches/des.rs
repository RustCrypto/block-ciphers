#![no_std]
#![feature(test)]

#[macro_use]
extern crate block_cipher_trait;
extern crate des;

bench_block_cipher!(des::Des, 8);
