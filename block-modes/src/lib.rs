//! This crate defines a simple trait used to define block ciphers
#![no_std]
extern crate block_cipher_trait;
pub extern crate block_padding;

mod utils;
mod traits;
pub use traits::{BlockMode, BlockModeIv, BlockModeError};


mod cbc;
pub use cbc::Cbc;
mod cfb;
pub use cfb::Cfb;
mod ctr64;
pub use ctr64::Ctr64;
mod ctr128;
pub use ctr128::Ctr128;
mod ecb;
pub use ecb::Ecb;
mod ofb;
pub use ofb::Ofb;
mod pcbc;
pub use pcbc::Pcbc;
