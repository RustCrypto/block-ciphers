#![cfg(feature = "ctr")]
#![feature(test)]
#[macro_use]
extern crate stream_cipher;
use aesni;

bench_sync!(aesni::Aes256Ctr);
