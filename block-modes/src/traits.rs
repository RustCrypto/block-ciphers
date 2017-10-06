use block_cipher_trait::{BlockCipher, NewFixKey, NewVarKey, InvalidKeyLength};
use generic_array::GenericArray;
use generic_array::typenum::Unsigned;

type Array<N> = GenericArray<u8, N>;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
/// Error for indicating failed unpadding process
pub struct UnpadError;

/// Trait for padding messages divided into blocks
pub trait Padding {
    /// Pads `block` filled with data up to `pos`
    fn pad(block: &mut [u8], pos: usize);

    /// Unpad given `data` by truncating it according to the used padding.
    /// In case of the malformed padding will return `UnpadError`
    fn unpad(data: &[u8]) -> Result<&[u8], UnpadError>;
}

pub trait BlockMode<C: BlockCipher> {
    fn encrypt_nopad(&mut self, buffer: &mut [u8]);
    fn decrypt_nopad(&mut self, buffer: &mut [u8]);
}

pub trait BlockModeIv<C: BlockCipher>: BlockMode<C> {
    fn new(cipher: C, iv: &Array<C::BlockSize>) -> Self;
}

pub trait BlockModeFixKey<C>: BlockModeIv<C> + Sized where C: NewFixKey {
    fn new(key: &Array<C::KeySize>, iv: &Array<C::BlockSize>) -> Self {
        <Self as BlockModeIv<C>>::new(C::new(key), iv)
    }
}

impl<T, C> BlockModeFixKey<C> for T
    where C: NewFixKey, T: BlockModeIv<C> + Sized { }

pub trait BlockModeVarKey<C>: BlockModeIv<C> + Sized where C: NewVarKey {
    fn new(key: &[u8], iv: &Array<C::BlockSize>)
        -> Result<Self, InvalidKeyLength>
    {
        Ok(<Self as BlockModeIv<C>>::new(C::new(key)?, iv))
    }
}

impl<T, C> BlockModeVarKey<C> for T
    where C: NewVarKey, T: BlockModeIv<C> + Sized { }

pub trait PadBlockMode<C: BlockCipher, P: Padding>: BlockMode<C> + Sized {
    fn encrypt(mut self, buffer: &mut [u8], pos: usize) -> &[u8] {
        let bs = C::BlockSize::to_usize();

        assert!(pos < buffer.len());
        assert_eq!(buffer.len() % bs, 0);

        // TODO: optimize, not optimal
        let n = {
            let (nopad, topad) = buffer.split_at_mut(pos - pos % bs);
            self.encrypt_nopad(nopad);

            P::pad(topad, pos % bs);
            self.encrypt_nopad(topad);
            nopad.len() + topad.len()
        };
        &buffer[..n]
    }

    fn decrypt(mut self, buffer: &mut [u8]) -> Result<&[u8], UnpadError> {
        let bs = C::BlockSize::to_usize();
        assert_eq!(buffer.len() % bs, 0);
        self.decrypt_nopad(buffer);
        P::unpad(buffer)
    }
}
