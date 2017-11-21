use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::generic_array::typenum::{U8, U16, U24, U32};
use block_cipher_trait::BlockCipher;
use core::mem;

use super::{Aes128, Aes192, Aes256};

type Block128 = GenericArray<u8, U16>;
type Block128x8 = GenericArray<GenericArray<u8, U16>, U8>;

#[inline(always)]
fn as_block_mut(val: &mut Block128) -> &mut [u8; 16] {
    assert_eq!(val.len(), 16);
    unsafe { mem::transmute(val) }
}

#[inline(always)]
fn as_block8_mut(val: &mut Block128x8) -> &mut [u8; 16*8] {
    assert_eq!(mem::size_of_val(val), 16*8);
    unsafe { mem::transmute(val) }
}

macro_rules! impl_trait {
    ($cipher:ty, $key_size:ty) => {
        impl BlockCipher for $cipher {
            type KeySize = $key_size;
            type BlockSize = U16;
            type ParBlocks = U8;

            #[inline]
            fn new(key: &GenericArray<u8, $key_size>) -> Self {
                Self::init(unsafe { mem::transmute(key) })
            }

            #[inline]
            fn encrypt_block(&self, block: &mut Block128) {
                self.encrypt(as_block_mut(block))
            }

            #[inline]
            fn decrypt_block(&self, block: &mut Block128) {
                self.decrypt(as_block_mut(block))
            }

            #[inline]
            fn encrypt_blocks(&self, blocks: &mut Block128x8) {
                self.encrypt8(as_block8_mut(blocks))
            }

            #[inline]
            fn decrypt_blocks(&self, blocks: &mut Block128x8) {
                self.decrypt8(as_block8_mut(blocks))
            }
        }
    }
}

impl_trait!(Aes128, U16);
impl_trait!(Aes192, U24);
impl_trait!(Aes256, U32);
