use block_cipher_trait::BlockCipher;
use block_cipher_trait::generic_array::typenum::Unsigned;
use block_cipher_trait::generic_array::GenericArray;
use block_padding::Padding;
use traits::BlockMode;
use utils::{xor, Block, lshift_by_one, to_blocks, to_blocks_uneven, swap};
use core::marker::PhantomData;
use std::clone::Clone;
use errors::{InvalidKeyIvLength, BlockModeError};
use std::vec::Vec;

/// Xor encrypt xor with ciphertext stealing (XTS) block cipher mode instance.
///
/// Note that `new` method ignores IV, so during initialization you can
/// just pass `Default::default()` instead.
///
/// [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#XTS
pub struct Xts<C: BlockCipher, P: Padding> {
    cipher: C,
    tweak: GenericArray<u8, C::BlockSize>,
    _p: PhantomData<P>,
}

impl<C: BlockCipher, P: Padding> Xts<C, P> {
    fn get_next_tweak(&mut self) {
        let last = C::BlockSize::to_usize() - 1;
        if (self.tweak[0] >> 7) > 0 {
            lshift_by_one(&mut self.tweak);
            self.tweak[last] ^= 0x87;
        } else {
            lshift_by_one(&mut self.tweak);
        }
    }
}

impl<C: BlockCipher, P: Padding> BlockMode<C, P> for Xts<C, P> {
    // If new is used to create the cipher, _iv already needs to be encrypted
    // by the second key so it can be used as a tweak value
    fn new(cipher: C, _iv: &Block<C>) -> Self {
        Self {
            cipher,
            tweak: _iv.clone(),
            _p: Default::default()
        }
    }

    fn new_var(key: &[u8], _iv: &[u8]) -> Result<Self, InvalidKeyIvLength> {
        if key.len() != C::KeySize::to_usize() * 2 || _iv.len() != C::BlockSize::to_usize() {
            return Err(InvalidKeyIvLength)
        }

        let cipher = C::new_varkey(&key[..C::KeySize::to_usize()]).map_err(|_| InvalidKeyIvLength)?;
        let tweak_cipher = C::new_varkey(&key[C::KeySize::to_usize()..]).map_err(|_| InvalidKeyIvLength)?;
        let mut tweak : GenericArray<u8, C::BlockSize> = Default::default();
        tweak[..C::BlockSize::to_usize()].copy_from_slice(_iv);
        tweak_cipher.encrypt_block(&mut tweak);

        Ok(
            Self {
            cipher,
            tweak,
            _p: Default::default()
            }
        )
    }

    // These function are not viable for an interface with XTS
    fn encrypt_blocks(&mut self, blocks: &mut [Block<C>]) {
        for block in blocks {
            xor(block, &self.tweak);
            self.cipher.encrypt_block(block);
            xor(block, &self.tweak);
            self.get_next_tweak();
        }
    }

    fn decrypt_blocks(&mut self, blocks: &mut [Block<C>]) {
        for block in blocks {
            xor(block, &self.tweak);
            self.cipher.decrypt_block(block);
            xor(block, &self.tweak);
            self.get_next_tweak();
        }
    }

    /// Encrypt message in-place.
    ///
    /// pos argument is ignored, since padding is not used with XTS.
    fn encrypt(
        mut self, buffer: &mut [u8], _: usize
    ) -> Result<&[u8], BlockModeError> {
        let bs = C::BlockSize::to_usize();
        let buffer_length = buffer.len();
        self.encrypt_blocks(to_blocks_uneven(buffer));
        if buffer_length % bs != 0 {
            let encrypted_len = (buffer_length / bs) * bs;
            let leftover = buffer_length - encrypted_len;
            let last_block_index = buffer_length - bs;
            assert!(buffer_length - last_block_index == bs);
            let mut last_block = &mut to_blocks(&mut buffer[last_block_index..])[0];
            swap::<C::BlockSize>(&mut last_block, bs - leftover);
            xor(&mut last_block, &self.tweak);
            self.cipher.encrypt_block(&mut last_block);
            xor(&mut last_block, &self.tweak);
        }
        Ok(buffer)
    }

    /// Decrypt message in-place.
    fn decrypt(mut self, buffer: &mut [u8]) -> Result<&[u8], BlockModeError> {
        let bs = C::BlockSize::to_usize();
        let buffer_length = buffer.len();
        let num_of_full_blocks = (buffer_length / bs) * bs;
        self.decrypt_blocks(&mut to_blocks_uneven(buffer)[..&num_of_full_blocks - 1]);
        if buffer_length % bs != 0 {
            let second_to_last_tweak = self.tweak.clone();
            self.get_next_tweak();

            let leftover = buffer_length - (buffer_length / bs) * bs;
            let last_block_index = buffer_length - bs;
            assert!(buffer_length - last_block_index == bs);

            let last_block = to_blocks(&mut buffer[last_block_index..]);
            xor(&mut last_block[0], &self.tweak);
            self.cipher.decrypt_block(&mut last_block[0]);
            xor(&mut last_block[0], &self.tweak);
            swap::<C::BlockSize>(&mut last_block[0], leftover);
            self.tweak = second_to_last_tweak;
        }
        let last_block = &mut to_blocks(buffer)[num_of_full_blocks - 1];
        xor(last_block, &self.tweak);
        self.cipher.decrypt_block(last_block);
        xor(last_block, &self.tweak);
        Ok(buffer)
    }

    /// Encrypt message and store result in vector.
    #[cfg(feature = "std")]
    fn encrypt_vec(mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut buf = Vec::from(plaintext);
        match self.encrypt(&mut buf, 0) { // 0 is ig
            Ok(_) => buf,
            _ => panic!()
        }
    }

    /// Encrypt message and store result in vector.
    #[cfg(feature = "std")]
    fn decrypt_vec(mut self, ciphertext: &[u8]) -> Result<Vec<u8>, BlockModeError> {
        let mut buf = Vec::from(ciphertext);
        match self.decrypt(&mut buf) {
            Ok(_) => Ok(buf),
            Err(e) => Err(e)
        }
    }
}
