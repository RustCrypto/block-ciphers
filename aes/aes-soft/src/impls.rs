pub use cipher::{BlockCipher, NewBlockCipher};

use cipher::{
    consts::{U11, U13, U15, U16, U24, U32, U8},
    generic_array::GenericArray,
};

use crate::{
    bitslice::{
        bit_slice_1x128_with_u32x4, bit_slice_1x16_with_u16, bit_slice_4x4_with_u16,
        bit_slice_fill_4x4_with_u32x4, decrypt_core, un_bit_slice_1x128_with_u32x4,
        un_bit_slice_1x16_with_u16, Bs8State,
    },
    consts::U32X4_0,
    expand::expand_key,
    fixslice::{self, FixsliceKeys128, FixsliceKeys192, FixsliceKeys256},
    simd::u32x4,
    Block, ParBlocks,
};

macro_rules! define_aes_impl {
    (
        $name:ident,
        $key_size:ty,
        $rounds:expr,
        $rounds2:ty,
        $fixslice_keys:ty,
        $fixslice_key_schedule:path,
        $fixslice_encrypt:path,
        $doc:expr
    ) => {
        #[doc=$doc]
        #[derive(Clone)]
        pub struct $name {
            enc_keys: $fixslice_keys,
            dec_keys: [Bs8State<u16>; $rounds],
            dec_keys8: [Bs8State<u32x4>; $rounds],
        }

        impl NewBlockCipher for $name {
            type KeySize = $key_size;

            #[inline]
            fn new(key: &GenericArray<u8, $key_size>) -> Self {
                let dk = expand_key::<$key_size, $rounds2>(key).1;
                let k8 = Bs8State(
                    U32X4_0, U32X4_0, U32X4_0, U32X4_0,
                    U32X4_0, U32X4_0, U32X4_0, U32X4_0
                );
                let mut c =  Self {
                    enc_keys: $fixslice_key_schedule(key),
                    dec_keys: [Bs8State(0, 0, 0, 0, 0, 0, 0, 0); $rounds],
                    dec_keys8: [k8; $rounds],
                };
                for i in 0..$rounds {
                    c.dec_keys[i] = bit_slice_4x4_with_u16(
                        dk[i][0], dk[i][1], dk[i][2], dk[i][3],
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
            fn encrypt_block(&self, block: &mut Block) {
	            let mut blocks = [Block::default(); 2];
                blocks[0].copy_from_slice(block);
                $fixslice_encrypt(&self.enc_keys, &mut blocks);
                block.copy_from_slice(&blocks[0]);
            }

            #[inline]
            fn decrypt_block(&self, block: &mut Block) {
                let mut bs = bit_slice_1x16_with_u16(block);
                bs = decrypt_core(&bs, &self.dec_keys);
                un_bit_slice_1x16_with_u16(&bs, block);
            }

            #[inline]
            fn encrypt_blocks(&self, blocks: &mut ParBlocks) {
                for chunk in blocks.chunks_mut(2) {
                    $fixslice_encrypt(&self.enc_keys, chunk);
                }
            }

            #[inline]
            fn decrypt_blocks(&self, blocks: &mut ParBlocks) {
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

define_aes_impl!(
    Aes128,
    U16,
    11,
    U11,
    FixsliceKeys128,
    fixslice::aes128_key_schedule,
    fixslice::aes128_encrypt,
    "AES-128 block cipher instance"
);

define_aes_impl!(
    Aes192,
    U24,
    13,
    U13,
    FixsliceKeys192,
    fixslice::aes192_key_schedule,
    fixslice::aes192_encrypt,
    "AES-192 block cipher instance"
);

define_aes_impl!(
    Aes256,
    U32,
    15,
    U15,
    FixsliceKeys256,
    fixslice::aes256_key_schedule,
    fixslice::aes256_encrypt,
    "AES-256 block cipher instance"
);
