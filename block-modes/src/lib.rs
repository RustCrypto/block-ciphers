//! This crate defines a simple trait used to define block ciphers
//#![no_std]
extern crate block_cipher_trait;
pub extern crate block_padding;

use std as core;

pub mod traits;
mod utils;


mod ecb;
pub use ecb::Ecb;
mod cbc;
pub use cbc::Cbc;
pub mod cfb;
pub use cfb::Cfb;
mod ofb;
pub use ofb::Ofb;
mod pcbc;
pub use pcbc::Pcbc;

mod ctr;
pub use ctr::{Ctr128, Ctr64};
