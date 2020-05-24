#![no_std]
#![feature(test)]
#[macro_use]
extern crate block_cipher_trait;
extern crate blowfish;

bench!(blowfish::Blowfish, 16);
