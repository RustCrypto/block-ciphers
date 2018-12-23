#![no_std]
pub extern crate block_cipher_trait;
extern crate byteorder;
#[macro_use] extern crate opaque_debug;

mod consts;
mod des;
mod tdes;

use block_cipher_trait::BlockCipher;
use block_cipher_trait::generic_array;

pub use des::Des;
pub use tdes::{TdesEde2, TdesEde3, TdesEee2, TdesEee3};

