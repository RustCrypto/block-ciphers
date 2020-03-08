#![no_std]
#![feature(test)]
#[macro_use]
extern crate block_cipher_trait;
extern crate serpent;

use serpent::Serpent;

bench!(Serpent, 16);
