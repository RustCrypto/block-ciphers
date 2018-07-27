#![cfg(feature = "ctr")]
#![no_std]
#![feature(test)]
#[macro_use] extern crate stream_cipher;
extern crate aesni;

bench_fixed!(aesni::Aes256Ctr);
