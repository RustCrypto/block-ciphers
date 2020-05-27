#![no_std]
#![feature(test)]
#[macro_use]
extern crate block_cipher;
use des;

bench!(des::Des, 8);
