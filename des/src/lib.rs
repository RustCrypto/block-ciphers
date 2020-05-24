#![no_std]
#![forbid(unsafe_code)]
pub extern crate block_cipher_trait;
extern crate byteorder;
#[macro_use]
extern crate opaque_debug;

mod consts;
mod des;
mod tdes;

use block_cipher_trait::generic_array;
use block_cipher_trait::BlockCipher;

pub use des::Des;
pub use tdes::{TdesEde2, TdesEde3, TdesEee2, TdesEee3};
