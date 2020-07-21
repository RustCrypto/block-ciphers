pub use block_cipher::{BlockCipher, NewBlockCipher};

use block_cipher::consts::{U11, U13, U15, U16, U24, U32, U8};
use block_cipher::generic_array::GenericArray;

use crate::bitslice::{
    bit_slice_1x128_with_u32x4, bit_slice_1x16_with_u16, bit_slice_4x4_with_u16,
    bit_slice_fill_4x4_with_u32x4, decrypt_core, encrypt_core, un_bit_slice_1x128_with_u32x4,
    un_bit_slice_1x16_with_u16, Bs8State,
};
use crate::consts::U32X4_0;
use crate::expand::expand_key;
use crate::simd::u32x4;

pub type Block128 = GenericArray<u8, U16>;
pub type Block128x8 = GenericArray<GenericArray<u8, U16>, U8>;

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
            enc_keys8: [Bs8State<u32x4>; $rounds],
            dec_keys8: [Bs8State<u32x4>; $rounds],
        }

        impl NewBlockCipher for $name {
            type KeySize = $key_size;

            #[inline]
            fn new(key: &GenericArray<u8, $key_size>) -> Self {
                let (ek, dk) = expand_key::<$key_size, $rounds2>(key);
                let k8 = Bs8State(
                    U32X4_0, U32X4_0, U32X4_0, U32X4_0,
                    U32X4_0, U32X4_0, U32X4_0, U32X4_0
                );
                let mut c =  Self {
                    enc_keys: [Bs8State(0, 0, 0, 0, 0, 0, 0, 0); $rounds],
                    dec_keys: [Bs8State(0, 0, 0, 0, 0, 0, 0, 0); $rounds],
                    enc_keys8: [k8; $rounds],
                    dec_keys8: [k8; $rounds],
                };
                for i in 0..$rounds {
                    c.enc_keys[i] = bit_slice_4x4_with_u16(
                        ek[i][0], ek[i][1], ek[i][2], ek[i][3],
                    );
                    c.dec_keys[i] = bit_slice_4x4_with_u16(
                        dk[i][0], dk[i][1], dk[i][2], dk[i][3],
                    );
                    c.enc_keys8[i] = bit_slice_fill_4x4_with_u32x4(
                        ek[i][0], ek[i][1], ek[i][2], ek[i][3],
                    );
                    c.dec_keys8[i] = bit_slice_fill_4x4_with_u32x4(
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

            #[inline]
            fn encrypt_blocks(&self, blocks: &mut Block128x8) {
                #[allow(unsafe_code)]
                let blocks: &mut [u8; 16*8] = unsafe {
                    &mut *(blocks as *mut _ as *mut [u8; 128])
                };
                let bs = bit_slice_1x128_with_u32x4(blocks);
                let bs2 = encrypt_core(&bs, &self.enc_keys8);
                un_bit_slice_1x128_with_u32x4(bs2, blocks);
            }

            #[inline]
            fn decrypt_blocks(&self, blocks: &mut Block128x8) {
                #[allow(unsafe_code)]
                let blocks: &mut [u8; 16*8] = unsafe {
                    &mut *(blocks as *mut _ as *mut [u8; 128])
                };
                let bs = bit_slice_1x128_with_u32x4(blocks);
                let bs2 = decrypt_core(&bs, &self.dec_keys8);
                un_bit_slice_1x128_with_u32x4(bs2, blocks);
            }
        }

        opaque_debug::implement!($name);
    }
}

define_aes_impl!(Aes128, U16, 11, U11, "AES-128 block cipher instance");
define_aes_impl!(Aes192, U24, 13, U13, "AES-192 block cipher instance");
define_aes_impl!(Aes256, U32, 15, U15, "AES-256 block cipher instance");
