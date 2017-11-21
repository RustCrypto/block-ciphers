#![no_std]
extern crate block_cipher_trait as traits;
extern crate byte_tools;

mod consts;
mod des;
mod tdes;

pub use des::Des;
pub use tdes::{TdesEde3, TdesEee3, TdesEde2, TdesEee2};
