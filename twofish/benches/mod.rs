#![no_std]
#![feature(test)]
#[macro_use]
extern crate block_cipher_trait;
extern crate twofish;

bench!(twofish::Twofish, 16);
