#![no_std]
#![feature(test)]
#[macro_use]
extern crate block_cipher_trait;
extern crate magma;

bench!(magma::Magma, 32);
