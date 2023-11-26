#![no_std]

mod block_cipher;
mod core;

pub use crate::core::RC5;
pub use block_cipher::*;
