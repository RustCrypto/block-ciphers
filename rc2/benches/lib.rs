#![no_std]
#![feature(test)]
#[macro_use]
extern crate block_cipher_trait;
extern crate rc2;

bench!(rc2::Rc2, 16);
