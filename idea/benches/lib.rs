#![no_std]
#![feature(test)]

block_cipher::bench!(idea::Idea, 16);
