use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::generic_array::typenum::Unsigned;
use block_cipher_trait::BlockCipher;
use block_padding::Padding;
use traits::{BlockMode, BlockModeError, BlockModeIv};
use utils::{xor, ParBlocks};
use core::marker::PhantomData;
use core::slice;

/// Struct for the Cipher Block Chaining (CBC) block cipher mode of operation
pub struct Cbc<C: BlockCipher, P: Padding> {
    cipher: C,
    iv: GenericArray<u8, C::BlockSize>,
    _p: PhantomData<P>,
}

impl<C: BlockCipher, P: Padding> BlockModeIv<C, P> for Cbc<C, P> {
    fn new(cipher: C, iv: &GenericArray<u8, C::BlockSize>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
            _p: Default::default(),
        }
    }
}

impl<C: BlockCipher, P: Padding> BlockMode<C, P> for Cbc<C, P> {
    fn encrypt_nopad(
        &mut self, mut buffer: &mut [u8]
    ) -> Result<(), BlockModeError> {
        let bs = C::BlockSize::to_usize();
        if buffer.len() % bs != 0 {
            Err(BlockModeError)?
        }
        self.iv = {
            let mut iv = self.iv.as_slice();
            while buffer.len() >= bs {
                let (block, r) = { buffer }.split_at_mut(bs);
                buffer = r;
                xor(block, iv);
                self.cipher
                    .encrypt_block(GenericArray::from_mut_slice(block));
                iv = block;
            }
            GenericArray::clone_from_slice(iv)
        };
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
                let (blocks, r) = { buffer }.split_at_mut(bss);
                buffer = r;

                let mut blocks_copy = {
                    let ga_blocks = unsafe {
                        &mut *(blocks.as_mut_ptr()
                            as *mut ParBlocks<C::BlockSize, C::ParBlocks>)
                    };
                    let blocks_copy = ga_blocks.clone();
                    self.cipher.decrypt_blocks(ga_blocks);
                    blocks_copy
                };
                let next_iv = blocks_copy[pb - 1].clone();
                let blocks_copy = unsafe {
                    slice::from_raw_parts(
                        blocks_copy.as_mut_ptr() as *mut u8,
                        bss - bs,
                    )
                };

                xor(&mut blocks[..bs], self.iv.as_slice());
                xor(&mut blocks[bs..], blocks_copy);
                self.iv = next_iv;
            }
        }

        while buffer.len() >= bs {
            let (block, r) = { buffer }.split_at_mut(bs);
            buffer = r;
            let block_copy = GenericArray::clone_from_slice(block);
            self.cipher.decrypt_block(unsafe {
                &mut *(block.as_mut_ptr()
                    as *mut GenericArray<u8, C::BlockSize>)
            });
            xor(block, self.iv.as_slice());
            self.iv = block_copy;
        }

        Ok(())
    }
}
