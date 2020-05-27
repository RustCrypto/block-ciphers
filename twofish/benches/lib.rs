#![no_std]
#![feature(test)]
#[macro_use]
extern crate block_cipher;
use twofish;

bench!(twofish::Twofish, 16);
