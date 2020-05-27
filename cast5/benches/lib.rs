#![no_std]
#![feature(test)]
#[macro_use]
extern crate block_cipher;
use cast5;

bench!(cast5::Cast5, 16);
