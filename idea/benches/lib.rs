#![no_std]
#![feature(test)]

use block_cipher::bench;

bench!(idea::Idea, 16);
