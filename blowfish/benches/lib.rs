#![no_std]
#![feature(test)]
#[macro_use]
extern crate block_cipher;
use blowfish;

bench!(blowfish::Blowfish, 16);
