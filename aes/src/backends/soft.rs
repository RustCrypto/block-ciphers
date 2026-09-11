#![deny(unsafe_code)]
use crate::{Block, backends::soft::fixslice::BatchBlocks};
use cipher::{
    BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherEncBackend, BlockCipherEncClosure,
    BlockSizeUser, ParBlocks, ParBlocksSizeUser, consts::U16, inout::InOut,
};

#[path = "fixslice/mod.rs"]
pub(crate) mod fixslice;

#[cfg(feature = "hazmat")]
pub(crate) use fixslice::hazmat;

use fixslice::{MinWord, NativeBatchSize, NativeWord, Word};

macro_rules! impl_backend {
    (
        name = $name:tt,
        backend = $backend:tt,
        key_size = $key_size:literal,
        module = $module:ident,
        doc = $doc:expr,
    ) => {
        #[doc=$doc]
        #[doc = "block cipher"]
        #[derive(Clone, Copy)]
        pub(crate) struct $name {
            rk: fixslice::$module::RoundKeys<MinWord>,
        }

        impl $name {
            #[inline]
            pub(crate) fn new(key: &[u8; $key_size]) -> Self {
                let rk = fixslice::$module::key_schedule(key);
                Self { rk }
            }

            #[inline]
            pub(crate) fn encrypt(&self, f: impl BlockCipherEncClosure<BlockSize = U16>) {
                let rk = &self.rk;
                let rk_native = self.rk.map(Word::broadcast);
                let backend = $backend { rk, rk_native };
                f.call(&backend)
            }

            #[inline]
            pub(crate) fn decrypt(&self, f: impl BlockCipherDecClosure<BlockSize = U16>) {
                let rk = &self.rk;
                let rk_native = self.rk.map(Word::broadcast);
                let backend = $backend { rk, rk_native };
                f.call(&backend)
            }
        }

        #[doc=$doc]
        #[doc = "block cipher"]
        #[derive(Clone, Copy)]
        pub(crate) struct $backend<'a> {
            rk: &'a fixslice::$module::RoundKeys<MinWord>,
            rk_native: fixslice::$module::RoundKeys<NativeWord>,
        }

        impl BlockSizeUser for $backend<'_> {
            type BlockSize = U16;
        }

        impl ParBlocksSizeUser for $backend<'_> {
            type ParBlocksSize = NativeBatchSize;
        }

        impl BlockCipherEncBackend for $backend<'_> {
            #[inline(always)]
            fn encrypt_block(&self, mut block: InOut<'_, '_, Block>) {
                let mut blocks = BatchBlocks::<MinWord>::default();
                blocks[0] = block.clone_in().into();
                let res = fixslice::$module::encrypt(&self.rk, &blocks);
                *block.get_out() = res[0].into();
            }

            #[inline(always)]
            fn encrypt_par_blocks(&self, mut blocks: InOut<'_, '_, ParBlocks<Self>>) {
                let res = fixslice::$module::encrypt(&self.rk_native, blocks.get_in());
                *blocks.get_out() = res;
            }
        }

        impl BlockCipherDecBackend for $backend<'_> {
            #[inline(always)]
            fn decrypt_block(&self, mut block: InOut<'_, '_, Block>) {
                let mut blocks = BatchBlocks::<MinWord>::default();
                blocks[0] = block.clone_in();
                let res = fixslice::$module::decrypt(&self.rk, &blocks);
                *block.get_out() = res[0];
            }

            #[inline(always)]
            fn decrypt_par_blocks(&self, mut blocks: InOut<'_, '_, ParBlocks<Self>>) {
                let res = fixslice::$module::decrypt(&self.rk_native, blocks.get_in());
                *blocks.get_out() = res;
            }
        }
    };
}

impl_backend!(
    name = Aes128,
    backend = Aes128Backend,
    key_size = 16,
    module = aes128,
    doc = "AES-128",
);
impl_backend!(
    name = Aes192,
    backend = Aes192Backend,
    key_size = 24,
    module = aes192,
    doc = "AES-192",
);
impl_backend!(
    name = Aes256,
    backend = Aes256Backend,
    key_size = 32,
    module = aes256,
    doc = "AES-256",
);
