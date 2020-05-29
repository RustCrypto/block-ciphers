#![no_std]
#![feature(test)]

block_cipher::bench!(serpent::Serpent, 16);
