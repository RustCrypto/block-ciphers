#![no_std]
#[macro_use]
extern crate block_cipher_trait;
extern crate blowfish;

new_test!(blowfish_test, "blowfish", blowfish::Blowfish);
