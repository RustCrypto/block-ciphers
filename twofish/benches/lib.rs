#![no_std]
#![feature(test)]

block_cipher::bench!(twofish::Twofish, 16);
