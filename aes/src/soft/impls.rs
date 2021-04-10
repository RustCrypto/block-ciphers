//! Macros for implementing `Aes*` structs and the `BlockCipher` interface

use cipher::{
    consts::{U16, U24, U32, U2},
    generic_array::GenericArray,
    BlockProcessing, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit, InOutVal, InOutBuf, InResOutBuf,
};
use crate::{Block, Block2};

use super::fixslice::{self, FixsliceKeys128, FixsliceKeys192, FixsliceKeys256};

macro_rules! define_aes_impl {
    (
        $name:ident,
        $key_size:ty,
        $fixslice_keys:ty,
        $fixslice_key_schedule:path,
        $fixslice_decrypt:path,
        $fixslice_encrypt:path,
        $doc:expr
    ) => {
        #[doc=$doc]
        #[derive(Clone)]
        pub struct $name {
            keys: $fixslice_keys,
        }

        impl KeyInit for $name {
            type KeySize = $key_size;

            #[inline]
            fn new(key: &GenericArray<u8, $key_size>) -> Self {
                Self { keys: $fixslice_key_schedule(key) }
            }
        }

        impl BlockProcessing for $name {
            type BlockSize = U16;
        }

        impl BlockCipher for $name {}

        impl BlockEncrypt for $name {
            fn encrypt_block(&self, mut block: impl InOutVal<Block>) {
                let mut t = Block2::default();
                t[0] = *(block.get_in());
                *(block.get_out()) = $fixslice_encrypt(&self.keys, &t)[0];
            }

            fn encrypt_blocks(
                &self,
                mut blocks: InOutBuf<'_, '_, Block>,
                proc: impl FnMut(InResOutBuf<'_, '_, '_, Block>),
            ) {
                blocks.chunks::<U2, _, _, _, _>(
                    &self.keys,
                    |keys, inc, res| *res = $fixslice_encrypt(keys, inc),
                    |keys, inc, res| {
                        debug_assert_eq!(inc.len(), 1);
                        res[0] = inc[0];
                        res[0] = $fixslice_encrypt(
                            keys,
                            &res
                        )[0];
                    },
                    proc,
                );
            }
        }

        impl BlockDecrypt for $name {
            #[inline]
            fn decrypt_block(&self, mut block: impl InOutVal<Block>) {
                let mut t = Block2::default();
                t[0] = *(block.get_in());
                *(block.get_out()) = $fixslice_decrypt(&self.keys, &t)[0];
            }

            fn decrypt_blocks(
                &self,
                mut blocks: InOutBuf<'_, '_, Block>,
                proc: impl FnMut(InResOutBuf<'_, '_, '_, Block>),
            ) {
                blocks.chunks::<U2, _, _, _, _>(
                    &self.keys,
                    |keys, inc, res| *res = $fixslice_decrypt(keys, inc),
                    |keys, inc, res| {
                        debug_assert_eq!(inc.len(), 1);
                        res[0] = inc[0];
                        res[0] = $fixslice_decrypt(
                            keys,
                            &res
                        )[0];
                    },
                    proc,
                );
            }
        }

        opaque_debug::implement!($name);
    }
}

define_aes_impl!(
    Aes128,
    U16,
    FixsliceKeys128,
    fixslice::aes128_key_schedule,
    fixslice::aes128_decrypt,
    fixslice::aes128_encrypt,
    "AES-128 block cipher instance"
);

define_aes_impl!(
    Aes192,
    U24,
    FixsliceKeys192,
    fixslice::aes192_key_schedule,
    fixslice::aes192_decrypt,
    fixslice::aes192_encrypt,
    "AES-192 block cipher instance"
);

define_aes_impl!(
    Aes256,
    U32,
    FixsliceKeys256,
    fixslice::aes256_key_schedule,
    fixslice::aes256_decrypt,
    fixslice::aes256_encrypt,
    "AES-256 block cipher instance"
);
