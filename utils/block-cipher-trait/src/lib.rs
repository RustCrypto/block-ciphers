//! This crate defines a simple trait used to define block ciphers
#![no_std]
extern crate generic_array;

use generic_array::{GenericArray, ArrayLength};

pub type Block<BlockSize> = GenericArray<u8, BlockSize>;

pub trait BlockCipher {
    type BlockSize: ArrayLength<u8>;

    fn new(key: &[u8]) -> Self;

    fn encrypt_block(&self, input: &Block<Self::BlockSize>,
                     output: &mut Block<Self::BlockSize>);

    fn decrypt_block(&self, input: &Block<Self::BlockSize>,
                     output: &mut Block<Self::BlockSize>);
}

/*
pub trait BlockEncryptorX8 {
    fn block_size(&self) -> usize;
    fn encrypt_block_x8(&self, input: &[u8], output: &mut [u8]);
}

pub trait BlockDecryptorX8 {
    fn block_size(&self) -> usize;
    fn decrypt_block_x8(&self, input: &[u8], output: &mut [u8]);
}*/
