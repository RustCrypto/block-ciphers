//! This crate defines a simple trait used to define block ciphers
#![no_std]
extern crate generic_array;

use generic_array::{GenericArray, ArrayLength};
use generic_array::typenum::Unsigned;

pub type Block<BlockSize> = GenericArray<u8, BlockSize>;

pub trait BlockCipher {
    type BlockSize: ArrayLength<u8>;

    fn encrypt_block(&self, input: &Block<Self::BlockSize>,
                     output: &mut Block<Self::BlockSize>);

    fn decrypt_block(&self, input: &Block<Self::BlockSize>,
                     output: &mut Block<Self::BlockSize>);
}

pub trait BlockCipherFixKey:BlockCipher {
    type KeySize: ArrayLength<u8>;

    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self;
}

pub trait BlockCipherVarKey:BlockCipher {
    fn new(key: &[u8]) -> Self;
}


/// Temporary here before it's merged into generic-array
#[inline]
pub fn from_slice<T, N: ArrayLength<T>>(slice: &[T]) -> &GenericArray<T, N> {
    assert_eq!(slice.len(), N::to_usize());
    unsafe {
        &*(slice.as_ptr() as *const GenericArray<T, N>)
    }
}

impl<B: BlockCipherFixKey> BlockCipherVarKey for B {
    fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), B::KeySize::to_usize());
        B::new(from_slice(key))
    }
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
