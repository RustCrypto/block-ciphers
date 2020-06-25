pub use block_cipher::{BlockCipher, NewBlockCipher};

use block_cipher::consts::{U11, U13, U15, U16, U24, U32, U8};
use block_cipher::generic_array::GenericArray;

use crate::bitslice::{
    bit_slice_1x16_with_u16, bit_slice_4x4_with_u16,
    decrypt_core, encrypt_core,
    un_bit_slice_1x16_with_u16, Bs8State,
};
use crate::expand::expand_key;

pub type Block128 = GenericArray<u8, U16>;

macro_rules! define_aes_impl {
    (
        $name:ident,
        $key_size:ty,
        $rounds:expr,
        $rounds2:ty,
        $doc:expr
    ) => {
        #[doc=$doc]
        #[derive(Clone)]
        pub struct $name {
            enc_keys: [Bs8State<u16>; $rounds],
            dec_keys: [Bs8State<u16>; $rounds],
        }

        impl NewBlockCipher for $name {
            type KeySize = $key_size;

            #[inline]
            fn new(key: &GenericArray<u8, $key_size>) -> Self {
                let (ek, dk) = expand_key::<$key_size, $rounds2>(key);
                let mut c =  Self {
                    enc_keys: [Bs8State(0, 0, 0, 0, 0, 0, 0, 0); $rounds],
                    dec_keys: [Bs8State(0, 0, 0, 0, 0, 0, 0, 0); $rounds],
                };
                for i in 0..$rounds {
                    c.enc_keys[i] = bit_slice_4x4_with_u16(
                        ek[i][0], ek[i][1], ek[i][2], ek[i][3],
                    );
                    c.dec_keys[i] = bit_slice_4x4_with_u16(
                        dk[i][0], dk[i][1], dk[i][2], dk[i][3],
                    );
                }
                c
            }
        }

        impl BlockCipher for $name {
            type BlockSize = U16;
            type ParBlocks = U8;

            #[inline]
            fn encrypt_block(&self, block: &mut Block128) {
                let mut bs = bit_slice_1x16_with_u16(block);
                bs = encrypt_core(&bs, &self.enc_keys);
                un_bit_slice_1x16_with_u16(&bs, block);
            }

            #[inline]
            fn decrypt_block(&self, block: &mut Block128) {
                let mut bs = bit_slice_1x16_with_u16(block);
                bs = decrypt_core(&bs, &self.dec_keys);
                un_bit_slice_1x16_with_u16(&bs, block);
            }
        }

        impl_opaque_debug!($name);
    }
}

define_aes_impl!(Aes128, U16, 11, U11, "AES-128 block cipher instance");
define_aes_impl!(Aes192, U24, 13, U13, "AES-192 block cipher instance");
define_aes_impl!(Aes256, U32, 15, U15, "AES-256 block cipher instance");
