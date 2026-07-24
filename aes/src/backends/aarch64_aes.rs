use cipher::{
    Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherEncBackend,
    BlockCipherEncClosure, BlockSizeUser, ParBlocks, ParBlocksSizeUser,
    consts::{U8, U16},
    inout::InOut,
};

mod encdec;
mod expand;

#[cfg(feature = "hazmat")]
pub(crate) mod hazmat;

use expand::RoundKeys;

type ParBlocksSize = U8;

pub(crate) type Aes128 = Aes<11>;
pub(crate) type Aes192 = Aes<13>;
pub(crate) type Aes256 = Aes<15>;

pub(crate) type Aes128Enc = AesEnc<11>;
pub(crate) type Aes192Enc = AesEnc<13>;
pub(crate) type Aes256Enc = AesEnc<15>;

pub(crate) type Aes128Dec = AesDec<11>;
pub(crate) type Aes192Dec = AesDec<13>;
pub(crate) type Aes256Dec = AesDec<15>;

#[derive(Clone, Copy)]
pub(crate) struct Aes<const RK: usize> {
    enc_rk: RoundKeys<RK>,
    dec_rk: RoundKeys<RK>,
}

impl<const RK: usize> Aes<RK> {
    #[inline]
    #[target_feature(enable = "aes")]
    // TODO(MSRV-1.86): remove `unsafe`
    pub(crate) unsafe fn encrypt(&self, f: impl BlockCipherEncClosure<BlockSize = U16>) {
        f.call(self);
    }

    #[inline]
    #[target_feature(enable = "aes")]
    // TODO(MSRV-1.86): remove `unsafe`
    pub(crate) unsafe fn decrypt(&self, f: impl BlockCipherDecClosure<BlockSize = U16>) {
        f.call(self);
    }
}

impl<const RK: usize> BlockSizeUser for Aes<RK> {
    type BlockSize = U16;
}

impl<const RK: usize> ParBlocksSizeUser for Aes<RK> {
    type ParBlocksSize = ParBlocksSize;
}

impl<const RK: usize> BlockCipherEncBackend for Aes<RK> {
    #[inline(always)]
    fn encrypt_block(&self, block: InOut<'_, '_, Block<Self>>) {
        // SAFETY: this trait impl is used only by the `Self::encrypt` method marked with
        // `#[target_feature(enable = "aes")]`
        unsafe { encdec::encrypt(&self.enc_rk, block) };
    }

    #[inline(always)]
    fn encrypt_par_blocks(&self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
        // SAFETY: this trait impl is used only by the `Self::encrypt` method marked with
        // `#[target_feature(enable = "aes")]`
        unsafe { encdec::encrypt_par(&self.enc_rk, blocks) };
    }
}

impl<const RK: usize> BlockCipherDecBackend for Aes<RK> {
    #[inline(always)]
    fn decrypt_block(&self, block: InOut<'_, '_, Block<Self>>) {
        // SAFETY: this trait impl is used only by the `Self::decrypt` method marked with
        // `#[target_feature(enable = "aes")]`
        unsafe { encdec::decrypt(&self.dec_rk, block) };
    }

    #[inline(always)]
    fn decrypt_par_blocks(&self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
        // SAFETY: this trait impl is used only by the `Self::decrypt` method marked with
        // `#[target_feature(enable = "aes")]`
        unsafe { encdec::decrypt_par(&self.dec_rk, blocks) };
    }
}

#[derive(Clone, Copy)]
pub(crate) struct AesEnc<const RK: usize> {
    enc_rk: RoundKeys<RK>,
}

impl<const RK: usize> AesEnc<RK> {
    #[inline]
    #[target_feature(enable = "aes")]
    // TODO(MSRV-1.86): remove `unsafe`
    pub(crate) unsafe fn as_encdec(&self) -> Aes<RK> {
        let enc_rk = self.enc_rk;
        let dec_rk = unsafe { expand::inv_expanded_keys(&enc_rk) };
        Aes { enc_rk, dec_rk }
    }

    #[inline]
    #[target_feature(enable = "aes")]
    // TODO(MSRV-1.86): remove `unsafe`
    pub(crate) unsafe fn as_dec(&self) -> AesDec<RK> {
        let dec_rk = unsafe { expand::inv_expanded_keys(&self.enc_rk) };
        AesDec { dec_rk }
    }

    #[inline]
    #[target_feature(enable = "aes")]
    // TODO(MSRV-1.86): remove `unsafe`
    pub(crate) unsafe fn encrypt(&self, f: impl BlockCipherEncClosure<BlockSize = U16>) {
        f.call(self)
    }
}

impl<const RK: usize> BlockSizeUser for AesEnc<RK> {
    type BlockSize = U16;
}

impl<const RK: usize> ParBlocksSizeUser for AesEnc<RK> {
    type ParBlocksSize = ParBlocksSize;
}

impl<const RK: usize> BlockCipherEncBackend for AesEnc<RK> {
    #[inline(always)]
    fn encrypt_block(&self, block: InOut<'_, '_, Block<Self>>) {
        // SAFETY: this trait impl is used only by the `Self::encrypt` method marked with
        // `#[target_feature(enable = "aes")]`
        unsafe { encdec::encrypt(&self.enc_rk, block) };
    }

    #[inline(always)]
    fn encrypt_par_blocks(&self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
        // SAFETY: this trait impl is used only by the `Self::encrypt` method marked with
        // `#[target_feature(enable = "aes")]`
        unsafe { encdec::encrypt_par(&self.enc_rk, blocks) };
    }
}

#[derive(Clone, Copy)]
pub(crate) struct AesDec<const RK: usize> {
    dec_rk: RoundKeys<RK>,
}

impl<const RK: usize> AesDec<RK> {
    #[inline]
    #[target_feature(enable = "aes")]
    // TODO(MSRV-1.86): remove `unsafe`
    pub(crate) unsafe fn decrypt(&self, f: impl BlockCipherDecClosure<BlockSize = U16>) {
        f.call(self);
    }
}

impl<const RK: usize> BlockSizeUser for AesDec<RK> {
    type BlockSize = U16;
}

impl<const RK: usize> ParBlocksSizeUser for AesDec<RK> {
    type ParBlocksSize = ParBlocksSize;
}

impl<const RK: usize> BlockCipherDecBackend for AesDec<RK> {
    #[inline(always)]
    fn decrypt_block(&self, block: InOut<'_, '_, Block<Self>>) {
        // SAFETY: this trait impl is used only by the `Self::decrypt` method marked with
        // `#[target_feature(enable = "aes")]`
        unsafe { encdec::decrypt(&self.dec_rk, block) };
    }

    #[inline(always)]
    fn decrypt_par_blocks(&self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
        // SAFETY: this trait impl is used only by the `Self::decrypt` method marked with
        // `#[target_feature(enable = "aes")]`
        unsafe { encdec::decrypt_par(&self.dec_rk, blocks) };
    }
}

macro_rules! impl_key_init {
    ($name:ty, $name_enc:ty, $name_dec:ty, $key_size:literal) => {
        impl $name {
            #[inline]
            #[target_feature(enable = "aes")]
            // TODO(MSRV-1.86): remove `unsafe`
            pub(crate) unsafe fn new(key: &[u8; $key_size]) -> Self {
                let enc_rk = unsafe { expand::expand_key(key) };
                let dec_rk = unsafe { expand::inv_expanded_keys(&enc_rk) };
                Self { enc_rk, dec_rk }
            }
        }

        impl $name_enc {
            #[inline]
            #[target_feature(enable = "aes")]
            // TODO(MSRV-1.86): remove `unsafe`
            pub(crate) unsafe fn new(key: &[u8; $key_size]) -> Self {
                let enc_rk = unsafe { expand::expand_key(key) };
                Self { enc_rk }
            }
        }

        impl $name_dec {
            #[inline]
            #[target_feature(enable = "aes")]
            // TODO(MSRV-1.86): remove `unsafe`
            pub(crate) unsafe fn new(key: &[u8; $key_size]) -> Self {
                let enc_rk = unsafe { expand::expand_key(key) };
                let dec_rk = unsafe { expand::inv_expanded_keys(&enc_rk) };
                Self { dec_rk }
            }
        }
    };
}

impl_key_init!(Aes128, Aes128Enc, Aes128Dec, 16);
impl_key_init!(Aes192, Aes192Enc, Aes192Dec, 24);
impl_key_init!(Aes256, Aes256Enc, Aes256Dec, 32);
