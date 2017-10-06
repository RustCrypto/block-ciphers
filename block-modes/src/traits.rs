use super::BlockCipher;
use generic_array::typenum::Unsigned;

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

pub trait BlockMode<C: BlockCipher, P: Padding>: Sized {
    fn encrypt_nopad(&mut self, buffer: &mut [u8]);
    fn decrypt_nopad(&mut self, buffer: &mut [u8]);

    fn encrypt(mut self, buffer: &mut [u8], pos: usize) -> &[u8] {
        let bs = C::BlockSize::to_usize();

        assert!(pos < buffer.len());
        assert_eq!(buffer.len() % bs, 0);

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
