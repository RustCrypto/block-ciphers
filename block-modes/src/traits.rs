use block_cipher_trait::{BlockCipher, InvalidKeyLength};
use block_cipher_trait::generic_array::GenericArray;
use block_cipher_trait::generic_array::typenum::Unsigned;
use block_padding::Padding;

type Array<N> = GenericArray<u8, N>;

#[derive(Clone, Copy, Debug)]
pub struct BlockModeError;

pub trait BlockMode<C: BlockCipher, P: Padding>: Sized {
    fn encrypt_nopad(&mut self, buffer: &mut [u8])
        -> Result<(), BlockModeError>;
    fn decrypt_nopad(&mut self, buffer: &mut [u8])
        -> Result<(), BlockModeError>;

    fn encrypt_pad(mut self, buffer: &mut [u8], pos: usize)
        -> Result<&[u8], BlockModeError>
    {
        let bs = C::BlockSize::to_usize();
        let buf = P::pad(buffer, pos, bs).map_err(|_| BlockModeError)?;
        self.encrypt_nopad(buf)?;
        Ok(buf)
    }

    fn decrypt_pad(mut self, buffer: &mut [u8])
        -> Result<&[u8], BlockModeError>
    {
        let bs = C::BlockSize::to_usize();
        if buffer.len() % bs != 0 { Err(BlockModeError)? }
        self.decrypt_nopad(buffer)?;
        P::unpad(buffer).map_err(|_| BlockModeError)
    }
}

pub trait BlockModeIv<C: BlockCipher, P: Padding>: BlockMode<C, P> + Sized {
    fn new(cipher: C, iv: &Array<C::BlockSize>) -> Self;

    fn new_fixkey(key: &Array<C::KeySize>, iv: &Array<C::BlockSize>) -> Self {
        Self::new(C::new(key), iv)
    }

    fn new_varkey(key: &[u8], iv: &Array<C::BlockSize>)
        -> Result<Self, InvalidKeyLength>
    {
        C::new_varkey(key).map(|c| Self::new(c, iv))
    }
}
