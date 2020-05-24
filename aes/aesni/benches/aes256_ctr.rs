#![cfg(feature = "ctr")]
#![feature(test)]
#[macro_use] extern crate stream_cipher;
extern crate aesni;

bench_sync!(aesni::Aes256Ctr);
