#![no_std]
#![feature(test)]
#[macro_use]
extern crate block_cipher_trait;
extern crate cast5;

bench!(cast5::Cast5, 16);
