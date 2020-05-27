#![no_std]
#![feature(test)]
#[macro_use]
extern crate block_cipher;
use magma;

bench!(magma::Magma, 32);
