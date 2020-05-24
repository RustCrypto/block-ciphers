#![no_std]
#![feature(test)]
#[macro_use]
extern crate block_cipher_trait;
extern crate sm4;

bench!(sm4::Sm4, 16);
