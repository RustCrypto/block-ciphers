//! This crate defines a simple trait used to define block ciphers
#![no_std]
extern crate block_cipher_trait;

pub mod traits;
#[macro_use]
mod tools;

mod ecb;
pub use ecb::Ecb;
mod cbc;
pub use cbc::Cbc;
mod pcbc;
pub use pcbc::Pcbc;
pub mod cfb;
pub use cfb::Cfb;
mod ofb;
pub use ofb::Ofb;
mod ctr;
pub use ctr::{Ctr128, Ctr64};

pub mod paddings;
