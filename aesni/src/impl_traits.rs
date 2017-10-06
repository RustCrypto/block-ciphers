use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::generic_array::typenum::{U16, U24, U32, Unsigned};
use block_cipher_trait::{BlockCipher, NewFixKey, InvalidBufLength};
use core::mem;

use super::{Aes128, Aes192, Aes256};

type Block128 = GenericArray<u8, U16>;

#[inline(always)]
fn as_block_mut(val: &mut [u8]) -> &mut [u8; 16] {
    assert_eq!(val.len(), 16);
    unsafe { &mut *(val.as_mut_ptr() as *mut [u8; 16]) }
}

#[inline(always)]
fn as_block8_mut(val: &mut [u8]) -> &mut [u8; 16*8] {
    assert_eq!(val.len(), 16*8);
    unsafe{ &mut *(val.as_mut_ptr() as *mut [u8; 16*8]) }
}

macro_rules! impl_trait {
    ($cipher:ty, $key_size:ty) => {
        impl NewFixKey for $cipher {
            type KeySize = $key_size;

            #[inline]
            fn new(key: &GenericArray<u8, $key_size>) -> Self {
                Self::init(unsafe { mem::transmute(key) })
            }
        }

        impl BlockCipher for $cipher {
            type BlockSize = U16;

            #[inline]
            fn encrypt_block(&self, block: &mut Block128) {
                self.encrypt(as_block_mut(block.as_mut_slice()))
            }

            #[inline]
            fn decrypt_block(&self, block: &mut Block128) {
                self.decrypt(as_block_mut(block.as_mut_slice()))
            }

            #[inline]
            fn encrypt_blocks(&self, mut buf: &mut [u8])
                -> Result<(), InvalidBufLength>
            {
                let bs = Self::BlockSize::to_usize();
                if buf.len() % bs != 0 { return Err(InvalidBufLength); }

                while buf.len() >= 8*bs {
                    let (chunk, r) = {buf}.split_at_mut(8*bs);
                    buf = r;
                    self.encrypt8(as_block8_mut(chunk));
                }

                for block in buf.chunks_mut(bs) {
                    self.encrypt(as_block_mut(block));
                }
                Ok(())
            }

            #[inline]
            fn decrypt_blocks(&self, mut buf: &mut [u8])
                -> Result<(), InvalidBufLength>
            {
                let bs = Self::BlockSize::to_usize();
                if buf.len() % bs != 0 { return Err(InvalidBufLength); }

                while buf.len() >= 8*bs {
                    let (chunk, r) = {buf}.split_at_mut(8*bs);
                    buf = r;
                    self.decrypt8(as_block8_mut(chunk));
                }

                for block in buf.chunks_mut(bs) {
                    self.decrypt(as_block_mut(block));
                }
                Ok(())
            }
        }
    }
}

impl_trait!(Aes128, U16);
impl_trait!(Aes192, U24);
impl_trait!(Aes256, U32);
