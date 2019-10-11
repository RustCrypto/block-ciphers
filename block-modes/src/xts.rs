use block_cipher_trait::BlockCipher;
use block_cipher_trait::generic_array::typenum::Unsigned;
use block_cipher_trait::generic_array::GenericArray;
use block_padding::Padding;
use traits::BlockMode;
use errors::InvalidKeyIvLength;
use utils::{xor, Block, lshift_by_one};
use core::marker::PhantomData;
use std::clone::Clone;

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
    fn get_next_tweak(mut tweak: GenericArray<u8, C::BlockSize>) -> GenericArray<u8, C::BlockSize> {
        let last = C::BlockSize::to_usize() - 1;
        if (tweak[0] >> 7) > 0 {
            lshift_by_one(&mut tweak);
            tweak[last] ^= 0x87;
        } else {
            lshift_by_one(&mut tweak);
        }
        tweak
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

    fn encrypt_blocks(&mut self, blocks: &mut [Block<C>]) {
        let mut tweak = self.tweak.clone();
        for block in blocks {
            xor(block, &tweak);
            self.cipher.encrypt_block(block);
            xor(block, &tweak);
            tweak = Self::get_next_tweak(tweak);
        }
    }

    fn decrypt_blocks(&mut self, blocks: &mut [Block<C>]) {
        let mut tweak = self.tweak.clone();
        for block in blocks {
            xor(block, &tweak);
            self.cipher.decrypt_block(block);
            xor(block, &tweak);
            tweak = Self::get_next_tweak(tweak);
        }
    }
}
