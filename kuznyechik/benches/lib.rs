#![no_std]
#![feature(test)]

use block_cipher::bench;

bench!(kuznyechik::Kuznyechik, 32);
