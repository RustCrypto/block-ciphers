use crate::{
    traits::{BlockMode, IvState},
    utils::{xor, Block, ParBlocks},
};
use block_padding::Padding;
use cipher::{
    generic_array::{typenum::Unsigned, GenericArray},
    BlockCipher, BlockEncrypt,
};
use core::{marker::PhantomData, ptr};

/// [Cipher feedback][1] (CFB) block mode instance with a full block feedback.
///
/// [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_(CFB)
#[derive(Clone)]
pub struct Cfb<C: BlockCipher + BlockEncrypt, P: Padding> {
    cipher: C,
    iv: GenericArray<u8, C::BlockSize>,
    _p: PhantomData<P>,
}

impl<C, P> BlockMode<C, P> for Cfb<C, P>
where
    C: BlockCipher + BlockEncrypt,
    P: Padding,
{
    type IvSize = C::BlockSize;

    fn new(cipher: C, iv: &Block<C>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
            _p: Default::default(),
        }
    }

    fn encrypt_blocks(&mut self, blocks: &mut [Block<C>]) {
        for block in blocks {
            self.cipher.encrypt_block(&mut self.iv);
            xor_set1(block, self.iv.as_mut_slice());
        }
    }

    fn decrypt_blocks(&mut self, mut blocks: &mut [Block<C>]) {
        let pb = C::ParBlocks::to_usize();

        if blocks.len() > pb {
            // SAFETY: we have checked that `blocks` has enough elements
            #[allow(unsafe_code)]
            let mut par_iv = read_par_block::<C>(&blocks[..pb]);

            let (b, r) = { blocks }.split_at_mut(1);
            blocks = r;
            self.cipher.encrypt_block(&mut self.iv);
            xor(&mut b[0], &self.iv);

            // Remember IV for trailing blocks
            self.iv = blocks[blocks.len() - (blocks.len() % pb) - 1].clone();

            while blocks.len() >= 2 * pb {
                let next_par_iv = read_par_block::<C>(&blocks[pb - 1..2 * pb - 1]);
                self.cipher.encrypt_blocks(&mut par_iv);
                let (par_block, r) = { blocks }.split_at_mut(pb);
                blocks = r;

                for (a, b) in par_block.iter_mut().zip(par_iv.iter()) {
                    xor(a, b)
                }
                par_iv = next_par_iv;
            }

            self.cipher.encrypt_blocks(&mut par_iv);
            let (par_block, r) = { blocks }.split_at_mut(pb);
            blocks = r;

            for (a, b) in par_block.iter_mut().zip(par_iv[..pb].iter()) {
                xor(a, b)
            }
        }

        for block in blocks {
            self.cipher.encrypt_block(&mut self.iv);
            xor_set2(block, self.iv.as_mut_slice());
        }
    }
}

impl<C, P> IvState<C, P> for Cfb<C, P>
where
    C: BlockCipher + BlockEncrypt,
    P: Padding,
{
    fn iv_state(&self) -> GenericArray<u8, Self::IvSize> {
        self.iv.clone()
    }
}

#[inline(always)]
fn read_par_block<C: BlockCipher>(blocks: &[Block<C>]) -> ParBlocks<C> {
    assert!(blocks.len() >= C::ParBlocks::to_usize());
    // SAFETY: assert checks that `blocks` is long enough
    #[allow(unsafe_code)]
    unsafe {
        ptr::read(blocks.as_ptr() as *const ParBlocks<C>)
    }
}

#[inline(always)]
fn xor_set1(buf1: &mut [u8], buf2: &mut [u8]) {
    for (a, b) in buf1.iter_mut().zip(buf2) {
        let t = *a ^ *b;
        *a = t;
        *b = t;
    }
}

#[inline(always)]
fn xor_set2(buf1: &mut [u8], buf2: &mut [u8]) {
    for (a, b) in buf1.iter_mut().zip(buf2) {
        let t = *a;
        *a ^= *b;
        *b = t;
    }
}
