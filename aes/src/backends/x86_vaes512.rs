use super::x86_aes::RoundKeys;
use cipher::{
    Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherEncBackend,
    BlockCipherEncClosure, BlockSizeUser, ParBlocks, ParBlocksSizeUser,
    consts::{U16, U64},
    inout::InOut,
};

mod encdec;

pub(crate) type Aes128<'a> = Aes<'a, 11>;
pub(crate) type Aes192<'a> = Aes<'a, 13>;
pub(crate) type Aes256<'a> = Aes<'a, 15>;

#[derive(Clone, Copy)]
pub(crate) struct Aes<'a, const RK: usize> {
    rk: &'a RoundKeys<RK>,
    rk2: encdec::RoundKeys4<RK>,
}

impl<'a, const RK: usize> Aes<'a, RK> {
    #[inline]
    #[target_feature(enable = "avx512f,vaes")]
    // TODO(MSRV-1.86): remove `unsafe`
    pub(crate) unsafe fn encrypt(
        rk: &'a RoundKeys<RK>,
        f: impl BlockCipherEncClosure<BlockSize = U16>,
    ) {
        let rk2 = unsafe { encdec::broadcast_keys(rk) };
        let backend = Self { rk, rk2 };
        f.call(&backend)
    }

    #[inline]
    #[target_feature(enable = "avx512f,vaes")]
    // TODO(MSRV-1.86): remove `unsafe`
    pub(crate) unsafe fn decrypt(
        rk: &'a RoundKeys<RK>,
        f: impl BlockCipherDecClosure<BlockSize = U16>,
    ) {
        let rk2 = unsafe { encdec::broadcast_keys(rk) };
        let backend = Self { rk, rk2 };
        f.call(&backend)
    }
}

impl<const RK: usize> BlockSizeUser for Aes<'_, RK> {
    type BlockSize = U16;
}

// Block sizes are chosen based on AVX-512's 32 ZMM registers.
//
// Round keys use 11, 13, 15 registers for AES-128/192/256 respectively.
// It results in 21, 19, 17 registers available for blocks with each register containing 4 blocks.
// We use the closest power-of-two value.
// TODO: bench bigger cipher-specific values
impl<const RK: usize> ParBlocksSizeUser for Aes<'_, RK> {
    type ParBlocksSize = U64;
}

impl<const RK: usize> BlockCipherEncBackend for Aes<'_, RK> {
    #[inline(always)]
    fn encrypt_block(&self, block: InOut<'_, '_, Block<Self>>) {
        // SAFETY: this trait impl is used only by the `Self::encrypt` method marked with
        // `#[target_feature(enable = "vaavx512f,vaeses")]`
        unsafe { super::x86_aes::encrypt(&self.rk, block) };
    }

    #[inline(always)]
    fn encrypt_par_blocks(&self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
        // SAFETY: this trait impl is used only by the `Self::encrypt` method marked with
        // `#[target_feature(enable = "avx512f,vaes")]`
        unsafe { encdec::encrypt_par(&self.rk2, blocks) };
    }
}

impl<const RK: usize> BlockCipherDecBackend for Aes<'_, RK> {
    #[inline(always)]
    fn decrypt_block(&self, block: InOut<'_, '_, Block<Self>>) {
        // SAFETY: this trait impl is used only by the `Self::decrypt` method marked with
        // `#[target_feature(enable = "avx512f,vaes")]`
        unsafe { super::x86_aes::decrypt(&self.rk, block) };
    }

    #[inline(always)]
    fn decrypt_par_blocks(&self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
        // SAFETY: this trait impl is used only by the `Self::decrypt` method marked with
        // `#[target_feature(enable = "avx512f,vaes")]`
        unsafe { encdec::decrypt_par(&self.rk2, blocks) };
    }
}
