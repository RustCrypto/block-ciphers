#![no_std]
#[macro_use]
extern crate block_cipher;
use blowfish;

new_test!(blowfish_test, "blowfish", blowfish::Blowfish);
