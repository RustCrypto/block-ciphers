#![no_std]
pub extern crate block_cipher_trait;
extern crate byte_tools;
#[macro_use]
extern crate opaque_debug;

mod consts;
mod des;
mod tdes;

pub use des::Des;
pub use tdes::{TdesEde3, TdesEee3, TdesEde2, TdesEee2};
pub use block_cipher_trait::BlockCipher;

use block_cipher_trait::generic_array;
