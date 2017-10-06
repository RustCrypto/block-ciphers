//! This crate defines a simple trait used to define block ciphers
#![no_std]
#![feature(i128_type)]
extern crate generic_array;

mod traits;
#[macro_use]
mod tools;
pub mod ecb;
pub mod cbc;
pub mod pcbc;
pub mod cfb;
pub mod ofb;
pub mod ctr64;
pub mod ctr128;

pub mod paddings;

use generic_array::{GenericArray, ArrayLength};
use generic_array::typenum::Unsigned;

pub type Block<BlockSize> = GenericArray<u8, BlockSize>;

pub trait BlockCipher {
    type BlockSize: ArrayLength<u8>;

    fn encrypt_block(&self, block: &mut Block<Self::BlockSize>);

    fn decrypt_block(&self, block: &mut Block<Self::BlockSize>);

    fn encrypt_blocks(&self, blocks: &mut [u8]);

    fn decrypt_blocks(&self, blocks: &mut [u8]);
}

pub trait BlockCipherFixKey:BlockCipher {
    type KeySize: ArrayLength<u8>;

    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self;
}

pub trait NewVarKey {
    fn new(key: &[u8]) -> Self;
}

pub trait NewFixKey {
    type KeySize: ArrayLength<u8>;

    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self;
}

impl<B: NewFixKey> NewVarKey for B {
    fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), B::KeySize::to_usize());
        B::new(GenericArray::from_slice(key))
    }
}
