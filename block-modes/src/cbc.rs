//! [Cipher Block Chaining][1] (CBC) mode.
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC
use crate::{xor, xor_ret};
use cipher::{
    generic_array::GenericArray, Block, BlockCipher, BlockDecryptMut, BlockEncryptMut,
    BlockProcessing, InOutBuf, InOutVal, InResOutBuf, InnerIvInit, IvState,
};

/// CBC mode encryptor.
#[derive(Clone)]
pub struct Encrypt<C: BlockEncryptMut + BlockCipher> {
    cipher: C,
    iv: Block<C>,
}

impl<C: BlockEncryptMut + BlockCipher> BlockEncryptMut for Encrypt<C> {
    fn encrypt_block(&mut self, mut block: impl InOutVal<Block<Self>>) {
        let t = xor_ret(block.get_in(), &self.iv);
        self.cipher.encrypt_block((&t, block.get_out()));
        self.iv = block.get_out().clone();
    }
}

impl<C: BlockEncryptMut + BlockCipher> BlockProcessing for Encrypt<C> {
    type BlockSize = C::BlockSize;
}

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
    #[inline]
    fn iv_state(&self) -> GenericArray<u8, Self::IvSize> {
        self.iv.clone()
    }
}

/// CBC mode decryptor.
#[derive(Clone)]
pub struct Decrypt<C: BlockDecryptMut + BlockCipher> {
    cipher: C,
    iv: Block<C>,
}

impl<C: BlockDecryptMut + BlockCipher> BlockDecryptMut for Decrypt<C> {
    fn decrypt_block(&mut self, mut block: impl InOutVal<Block<Self>>) {
        let enc_block = block.get_in().clone();
        self.cipher.decrypt_block((&enc_block, block.get_out()));
        xor(block.get_out(), &self.iv);
        self.iv = enc_block;
    }

    fn decrypt_blocks(
        &mut self,
        blocks: InOutBuf<'_, '_, Block<Self>>,
        mut proc: impl FnMut(InResOutBuf<'_, '_, '_, Block<Self>>),
    ) {
        let iv = &mut self.iv;
        self.cipher.decrypt_blocks(blocks, |mut buf| {
            let len = buf.len();
            let (in_buf, res_buf) = buf.get_in_res();
            xor(&mut res_buf[0], iv);
            for i in 1..len {
                xor(&mut res_buf[i], &in_buf[i - 1]);
            }
            *iv = in_buf[len - 1].clone();
            proc(buf);
        });
    }
}

impl<C: BlockDecryptMut + BlockCipher> BlockProcessing for Decrypt<C> {
    type BlockSize = C::BlockSize;
}

impl<C: BlockDecryptMut + BlockCipher> InnerIvInit for Decrypt<C> {
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

impl<C: BlockDecryptMut + BlockCipher> IvState for Decrypt<C> {
    fn iv_state(&self) -> GenericArray<u8, Self::IvSize> {
        self.iv.clone()
    }
}
