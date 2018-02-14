use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::generic_array::typenum::Unsigned;
use block_padding::Padding;
use block_cipher_trait::BlockCipher;
use traits::{BlockMode, BlockModeIv, BlockModeError};
use tools::xor;
use core::marker::PhantomData;
use core::{mem, slice};

type ParBlocks<B, P> = GenericArray<GenericArray<u8, B>, P>;

pub struct Cfb<C: BlockCipher, P: Padding> {
    cipher: C,
    iv: GenericArray<u8, C::BlockSize>,
    _p: PhantomData<P>,
}

impl<C: BlockCipher, P: Padding> BlockModeIv<C, P> for Cfb<C, P> {
    fn new(cipher: C, iv: &GenericArray<u8, C::BlockSize>) -> Self {
        Self { cipher, iv: iv.clone(), _p: Default::default() }
    }
}

impl<C: BlockCipher, P: Padding> BlockMode<C, P> for Cfb<C, P> {
    fn encrypt_nopad(&mut self, mut buffer: &mut [u8])
        -> Result<(), BlockModeError>
    {
        let bs = C::BlockSize::to_usize();
        if buffer.len() % bs != 0 { Err(BlockModeError)? }

        while buffer.len() >= bs {
            let (block, r) = {buffer}.split_at_mut(bs);
            buffer = r;
            self.cipher.encrypt_block(&mut self.iv);
            xor(block, self.iv.as_slice());
            self.iv.clone_from_slice(block);
        }

        Ok(())

    }

    fn decrypt_nopad(&mut self, mut buffer: &mut [u8])
        -> Result<(), BlockModeError>
    {
        let bs = C::BlockSize::to_usize();
        let pb = C::ParBlocks::to_usize();
        if buffer.len() % bs != 0 { Err(BlockModeError)? }

        if buffer.len() == 0 { return Ok(()); }

        if pb != 1 {
            let bss = bs*pb;

            // we have checked that we have at least one block
            let (block, r) = {buffer}.split_at_mut(bs);
            buffer = r;
            self.cipher.encrypt_block(&mut self.iv);
            let mut next_iv = GenericArray::clone_from_slice(block);
            xor(block, self.iv.as_slice());

            while buffer.len() >= bss {
                let (mut blocks, r) = {buffer}.split_at_mut(bss);
                buffer = r;

                let mut ga_blocks: ParBlocks<C::BlockSize, C::ParBlocks> = unsafe {
                    // a bit of black magic, we are sure that there is a block
                    // before `blocks` which will be alive
                    let p = blocks.as_ptr().offset(-C::BlockSize::to_isize());
                    mem::transmute_copy(&*p)
                };

                next_iv = ga_blocks[bs-1].clone();

                self.cipher.encrypt_blocks(&mut ga_blocks);

                xor(&mut blocks, unsafe { slice::from_raw_parts(
                    ga_blocks.as_ptr() as *mut u8, bss
                )});
            }

            self.iv = next_iv;
        }

        while buffer.len() >= bs {
            let (block, r) = {buffer}.split_at_mut(bs);
            buffer = r;
            self.cipher.encrypt_block(&mut self.iv);
            let next_iv = GenericArray::clone_from_slice(block);
            xor(block, self.iv.as_slice());
            self.iv = next_iv;
        }

        Ok(())
    }
}
