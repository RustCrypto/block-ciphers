use block_cipher_trait::{BlockCipher, InvalidKeyLength};
use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::generic_array::typenum::Unsigned;
use block_padding::Padding;
use traits::{BlockMode, BlockModeError};
use core::marker::PhantomData;

type ParBlocks<B, P> = GenericArray<GenericArray<u8, B>, P>;

pub struct Ecb<C: BlockCipher, P: Padding> {
    cipher: C,
    _p: PhantomData<P>,
}

impl<C: BlockCipher, P: Padding> Ecb<C, P> {
    pub fn new(cipher: C) -> Self {
        Self {
            cipher,
            _p: Default::default(),
        }
    }

    pub fn new_fixkey(key: &GenericArray<u8, C::KeySize>) -> Self {
        Self::new(C::new(key))
    }

    pub fn new_varkey(key: &[u8]) -> Result<Self, InvalidKeyLength> {
        C::new_varkey(key).map(Self::new)
    }
}

impl<C: BlockCipher, P: Padding> BlockMode<C, P> for Ecb<C, P> {
    fn encrypt_nopad(
        &mut self, mut buffer: &mut [u8]
    ) -> Result<(), BlockModeError> {
        let bs = C::BlockSize::to_usize();
        let pb = C::ParBlocks::to_usize();
        if buffer.len() % bs != 0 {
            Err(BlockModeError)?
        }

        if pb != 1 {
            let bss = bs * pb;
            while buffer.len() >= bss {
                let (l, r) = { buffer }.split_at_mut(bss);
                buffer = r;
                self.cipher.encrypt_blocks(unsafe {
                    &mut *(l.as_mut_ptr()
                        as *mut ParBlocks<C::BlockSize, C::ParBlocks>)
                })
            }
        }

        while buffer.len() >= bs {
            let (l, r) = { buffer }.split_at_mut(bs);
            buffer = r;
            self.cipher.encrypt_block(unsafe {
                &mut *(l.as_mut_ptr() as *mut GenericArray<u8, C::BlockSize>)
            })
        }

        Ok(())
    }

    fn decrypt_nopad(
        &mut self, mut buffer: &mut [u8]
    ) -> Result<(), BlockModeError> {
        let bs = C::BlockSize::to_usize();
        let pb = C::ParBlocks::to_usize();
        if buffer.len() % bs != 0 {
            Err(BlockModeError)?
        }

        if pb != 1 {
            let bss = bs * pb;
            while buffer.len() >= bss {
                let (l, r) = { buffer }.split_at_mut(bss);
                buffer = r;
                self.cipher.decrypt_blocks(unsafe {
                    &mut *(l.as_mut_ptr()
                        as *mut ParBlocks<C::BlockSize, C::ParBlocks>)
                })
            }
        }

        while buffer.len() >= bs {
            let (l, r) = { buffer }.split_at_mut(bs);
            buffer = r;
            self.cipher.decrypt_block(unsafe {
                &mut *(l.as_mut_ptr() as *mut GenericArray<u8, C::BlockSize>)
            })
        }

        Ok(())
    }
}
