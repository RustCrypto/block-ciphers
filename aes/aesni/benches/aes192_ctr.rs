#![cfg(feature = "ctr")]
#![feature(test)]
use stream_cipher::bench_sync;

bench_sync!(aesni::Aes192Ctr);
