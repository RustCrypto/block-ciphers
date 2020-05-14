#![no_std]
#![feature(test)]
#[macro_use]
extern crate block_cipher_trait;
extern crate des;

bench!(des::Des, 8);
