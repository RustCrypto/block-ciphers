#![cfg(feature = "ctr")]
#![feature(test)]

#[cfg(feature = "ctr")]
cipher::stream_cipher_sync_bench!(aesni::Aes128Ctr);
