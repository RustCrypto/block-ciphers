//! [Cipher feedback][1] (CFB) mode with full block feedback.
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_(CFB)
use cipher::{
    generic_array::{ArrayLength, GenericArray},
    AsyncStreamCipher, Block, BlockCipher, BlockDecryptMut, BlockEncryptMut, BlockProcessing,
    InOutBuf, InOutVal, InResOutBuf, InnerIvInit, IvState,
};

/// CFB mode encryptor.
#[derive(Clone)]
pub struct Encrypt<C: BlockEncryptMut + BlockCipher> {
    cipher: C,
    iv: Block<C>,
}

impl<C: BlockEncryptMut + BlockCipher> BlockEncryptMut for Encrypt<C> {
    fn encrypt_block(&mut self, mut block: impl InOutVal<Block<Self>>) {
        self.cipher.encrypt_block(&mut self.iv);
        xor(&mut self.iv, block.get_in());
        *block.get_out() = self.iv.clone();
    }
}

impl<C: BlockEncryptMut + BlockCipher> BlockProcessing for Encrypt<C> {
    type BlockSize = C::BlockSize;
}

impl<C: BlockEncryptMut + BlockCipher> AsyncStreamCipher for Encrypt<C> {}

impl<C: BlockEncryptMut + BlockCipher> InnerIvInit for Encrypt<C> {
    type Inner = C;
    type IvSize = C::BlockSize;

    #[inline]
    fn inner_iv_init(cipher: C, iv: &GenericArray<u8, Self::IvSize>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
        }
    }
}

impl<C: BlockEncryptMut + BlockCipher> IvState for Encrypt<C> {
    fn iv_state(&self) -> GenericArray<u8, Self::IvSize> {
        self.iv.clone()
    }
}

/// CFB mode decryptor.
#[derive(Clone)]
pub struct Decrypt<C: BlockEncryptMut + BlockCipher> {
    cipher: C,
    iv: Block<C>,
}

impl<C: BlockEncryptMut + BlockCipher> BlockDecryptMut for Decrypt<C> {
    fn decrypt_block(&mut self, mut block: impl InOutVal<Block<Self>>) {
        let mut t = self.iv.clone();
        self.cipher.encrypt_block(&mut t);
        xor(&mut t, block.get_in());
        self.iv = block.get_in().clone();
        *block.get_out() = t;
    }

    fn decrypt_blocks(
        &mut self,
        blocks: InOutBuf<'_, '_, Block<Self>>,
        mut proc: impl FnMut(InResOutBuf<'_, '_, '_, Block<Self>>),
    ) {
        let mut enc_iv = self.iv.clone();
        self.cipher.encrypt_block(&mut enc_iv);
        let iv = &mut self.iv;
        self.cipher.encrypt_blocks(blocks, |mut buf| {
            let len = buf.len();
            let (in_buf, res_buf) = buf.get_in_res();
            for i in 0..len {
                xor(&mut enc_iv, &in_buf[i]);
                core::mem::swap(&mut res_buf[i], &mut enc_iv);
            }
            *iv = in_buf[len - 1].clone();
            proc(buf);
        });
    }
}

impl<C: BlockEncryptMut + BlockCipher> BlockProcessing for Decrypt<C> {
    type BlockSize = C::BlockSize;
}

impl<C: BlockEncryptMut + BlockCipher> AsyncStreamCipher for Decrypt<C> {}

impl<C: BlockEncryptMut + BlockCipher> InnerIvInit for Decrypt<C> {
    type Inner = C;
    type IvSize = C::BlockSize;

    #[inline]
    fn inner_iv_init(cipher: C, iv: &GenericArray<u8, Self::IvSize>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
        }
    }
}

impl<C: BlockEncryptMut + BlockCipher> IvState for Decrypt<C> {
    fn iv_state(&self) -> GenericArray<u8, Self::IvSize> {
        self.iv.clone()
    }
}

#[inline(always)]
fn xor<N: ArrayLength<u8>>(out: &mut GenericArray<u8, N>, buf: &GenericArray<u8, N>) {
    for (a, b) in out.iter_mut().zip(buf) {
        *a ^= *b;
    }
}
