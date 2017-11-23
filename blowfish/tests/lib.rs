#![no_std]
extern crate blowfish;
#[macro_use]
extern crate block_cipher_trait;

new_test!(blowfish_test, "blowfish", blowfish::Blowfish);
