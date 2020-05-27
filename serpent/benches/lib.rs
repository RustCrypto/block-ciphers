#![no_std]
#![feature(test)]

use block_cipher::bench;

bench!(serpent::Serpent, 16);
