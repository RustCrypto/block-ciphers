#![deny(unsafe_code)]
use crate::Block;
use cipher::{
    BlockCipherDecBackend, BlockCipherEncBackend, BlockSizeUser, ParBlocks, ParBlocksSizeUser,
    consts::U16, inout::InOut,
};

#[path = "fixslice/mod.rs"]
pub(crate) mod fixslice;

#[cfg(feature = "hazmat")]
pub(crate) use fixslice::hazmat;

use fixslice::{BatchBlocks, NativeBatchSize, NativeWord};

macro_rules! impl_backend {
    (
        name = $name:tt,
        key_size = $key_size:literal,
        module = $module:ident,
        doc = $doc:expr,
    ) => {
        #[doc=$doc]
        #[doc = "block cipher"]
        #[derive(Clone, Copy)]
        pub(crate) struct $name {
            keys: fixslice::$module::RoundKeys<NativeWord>,
        }

        impl $name {
            #[inline]
            pub(crate) fn new(key: &[u8; $key_size]) -> Self {
                let keys = fixslice::$module::key_schedule(key);
                Self { keys }
            }
        }

        impl BlockSizeUser for $name {
            type BlockSize = U16;
        }

        impl ParBlocksSizeUser for $name {
            type ParBlocksSize = NativeBatchSize;
        }

        impl BlockCipherEncBackend for $name {
            #[inline(always)]
            fn encrypt_block(&self, mut block: InOut<'_, '_, Block>) {
                let mut blocks = BatchBlocks::<NativeWord>::default();
                blocks[0] = block.clone_in().into();
                let res = fixslice::$module::encrypt(&self.keys, &blocks);
                *block.get_out() = res[0].into();
            }

            #[inline(always)]
            fn encrypt_par_blocks(&self, mut blocks: InOut<'_, '_, ParBlocks<Self>>) {
                let res = fixslice::$module::encrypt(&self.keys, blocks.get_in());
                *blocks.get_out() = res;
            }
        }

        impl BlockCipherDecBackend for $name {
            #[inline(always)]
            fn decrypt_block(&self, mut block: InOut<'_, '_, Block>) {
                let mut blocks = BatchBlocks::<NativeWord>::default();
                blocks[0] = block.clone_in();
                let res = fixslice::$module::decrypt(&self.keys, &blocks);
                *block.get_out() = res[0];
            }

            #[inline(always)]
            fn decrypt_par_blocks(&self, mut blocks: InOut<'_, '_, ParBlocks<Self>>) {
                let res = fixslice::$module::decrypt(&self.keys, blocks.get_in());
                *blocks.get_out() = res;
            }
        }
    };
}

impl_backend!(
    name = Aes128,
    key_size = 16,
    module = aes128,
    doc = "AES-128",
);
impl_backend!(
    name = Aes192,
    key_size = 24,
    module = aes192,
    doc = "AES-192",
);
impl_backend!(
    name = Aes256,
    key_size = 32,
    module = aes256,
    doc = "AES-256",
);
