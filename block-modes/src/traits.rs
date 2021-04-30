#[cfg(feature = "alloc")]
pub use alloc::vec::Vec;

use crate::{
    errors::{BlockModeError, InvalidKeyIvLength},
    utils::{to_blocks, Block, Key},
};
use block_padding::Padding;
use cipher::{
    generic_array::{typenum::Unsigned, ArrayLength, GenericArray},
    BlockCipher, NewBlockCipher,
};

/// Trait for a block cipher mode of operation that is used to apply a block cipher
/// operation to input data to transform it into a variable-length output message.
pub trait BlockMode<C: BlockCipher, P: Padding>: Sized {
    /// Initialization Vector size.
    type IvSize: ArrayLength<u8>;

    /// Create a new block mode instance from initialized block cipher and IV.
    fn new(cipher: C, iv: &GenericArray<u8, Self::IvSize>) -> Self;

    /// Create a new block mode instance from fixed sized key and IV.
    fn new_fix(key: &Key<C>, iv: &GenericArray<u8, Self::IvSize>) -> Self
    where
        C: NewBlockCipher,
    {
        Self::new(C::new(key), iv)
    }

    /// Create a new block mode instance from variable size key and IV.
    ///
    /// Returns an error if key or IV have unsupported length.
    fn new_from_slices(key: &[u8], iv: &[u8]) -> Result<Self, InvalidKeyIvLength>
    where
        C: NewBlockCipher,
    {
        if iv.len() != Self::IvSize::USIZE {
            return Err(InvalidKeyIvLength);
        }
        let iv = GenericArray::from_slice(iv);
        let cipher = C::new_from_slice(key).map_err(|_| InvalidKeyIvLength)?;
        Ok(Self::new(cipher, iv))
    }

    /// Encrypt blocks of data
    fn encrypt_blocks(&mut self, blocks: &mut [Block<C>]);

    /// Decrypt blocks of data
    fn decrypt_blocks(&mut self, blocks: &mut [Block<C>]);

    /// Encrypt message in-place.
    ///
    /// `&buffer[..pos]` is used as a message and `&buffer[pos..]` as a reserved
    /// space for padding. The padding space should be big enough for padding,
    /// otherwise method will return `Err(BlockModeError)`.
    fn encrypt(mut self, buffer: &mut [u8], pos: usize) -> Result<&[u8], BlockModeError> {
        let bs = C::BlockSize::to_usize();
        let buf = P::pad(buffer, pos, bs).map_err(|_| BlockModeError)?;
        self.encrypt_blocks(to_blocks(buf));
        Ok(buf)
    }

    /// Decrypt message in-place.
    ///
    /// Returns an error if `buffer` length is not multiple of block size and
    /// if after decoding message has malformed padding.
    fn decrypt(mut self, buffer: &mut [u8]) -> Result<&[u8], BlockModeError> {
        let bs = C::BlockSize::to_usize();
        if buffer.len() % bs != 0 {
            return Err(BlockModeError);
        }
        self.decrypt_blocks(to_blocks(buffer));
        P::unpad(buffer).map_err(|_| BlockModeError)
    }

    /// Encrypt message and store result in vector.
    #[cfg(feature = "alloc")]
    fn encrypt_vec(mut self, plaintext: &[u8]) -> Vec<u8> {
        let bs = C::BlockSize::to_usize();
        let pos = plaintext.len();
        let n = pos + bs;
        let mut buf = Vec::with_capacity(n);
        buf.extend_from_slice(plaintext);
        // prepare space for padding
        let block: Block<C> = Default::default();
        buf.extend_from_slice(&block[..n - pos]);

        let n = P::pad(&mut buf, pos, bs)
            .expect("enough space for padding is allocated")
            .len();
        buf.truncate(n);
        self.encrypt_blocks(to_blocks(&mut buf));
        buf
    }

    /// Encrypt message and store result in vector.
    #[cfg(feature = "alloc")]
    fn decrypt_vec(mut self, ciphertext: &[u8]) -> Result<Vec<u8>, BlockModeError> {
        let bs = C::BlockSize::to_usize();
        if ciphertext.len() % bs != 0 {
            return Err(BlockModeError);
        }
        let mut buf = ciphertext.to_vec();
        self.decrypt_blocks(to_blocks(&mut buf));
        let n = P::unpad(&buf).map_err(|_| BlockModeError)?.len();
        buf.truncate(n);
        Ok(buf)
    }
}

/// Trait for a BlockMode, used to obtain the current state in the form of an IV
/// that can initialize a BlockMode later and resume the original operation.
///
/// The IV value SHOULD be used for resuming operations only and MUST NOT be
/// exposed to attackers. Failing to comply with this requirement breaks
/// unpredictability and opens attack venues (see e.g. [1], sec. 3.6.2).
///
/// [1]: https://www.cs.umd.edu/~jkatz/imc.html
pub trait IvState<C, P>: BlockMode<C, P>
where
    C: BlockCipher,
    P: Padding,
{
    /// Returns the IV needed to process the following block. This value MUST
    /// NOT be exposed to attackers.
    fn iv_state(&self) -> GenericArray<u8, Self::IvSize>;
}
