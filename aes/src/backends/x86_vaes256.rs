use super::x86_aes::RoundKeys;
use cipher::{
    Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherEncBackend,
    BlockCipherEncClosure, BlockSizeUser, ParBlocks, ParBlocksSizeUser,
    consts::{U16, U30},
    inout::InOut,
};

mod encdec;

pub(crate) type Aes128<'a> = Aes<'a, 11>;
pub(crate) type Aes192<'a> = Aes<'a, 13>;
pub(crate) type Aes256<'a> = Aes<'a, 15>;

#[derive(Clone, Copy)]
pub(crate) struct Aes<'a, const RK: usize> {
    rk: &'a RoundKeys<RK>,
    rk2: encdec::RoundKeys2<RK>,
}

impl<'a, const RK: usize> Aes<'a, RK> {
    #[inline]
    #[target_feature(enable = "vaes")]
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
    #[target_feature(enable = "vaes")]
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

// Block size of 30 is chosen based on AVX2's 16 YMM registers.
//
// - 1 register holds round key
// - 15 registers hold 2 data blocks
impl<const RK: usize> ParBlocksSizeUser for Aes<'_, RK> {
    type ParBlocksSize = U30;
}

impl<const RK: usize> BlockCipherEncBackend for Aes<'_, RK> {
    #[inline(always)]
    fn encrypt_block(&self, block: InOut<'_, '_, Block<Self>>) {
        // SAFETY: this trait impl is used only by the `Self::encrypt` method marked with
        // `#[target_feature(enable = "vaes")]`
        unsafe { super::x86_aes::encrypt(&self.rk, block) };
    }

    #[inline(always)]
    fn encrypt_par_blocks(&self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
        // SAFETY: this trait impl is used only by the `Self::encrypt` method marked with
        // `#[target_feature(enable = "vaes")]`
        unsafe { encdec::encrypt_par(&self.rk2, blocks) };
    }
}

impl<const RK: usize> BlockCipherDecBackend for Aes<'_, RK> {
    #[inline(always)]
    fn decrypt_block(&self, block: InOut<'_, '_, Block<Self>>) {
        // SAFETY: this trait impl is used only by the `Self::decrypt` method marked with
        // `#[target_feature(enable = "vaes")]`
        unsafe { super::x86_aes::decrypt(&self.rk, block) };
    }

    #[inline(always)]
    fn decrypt_par_blocks(&self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
        // SAFETY: this trait impl is used only by the `Self::decrypt` method marked with
        // `#[target_feature(enable = "vaes")]`
        unsafe { encdec::decrypt_par(&self.rk2, blocks) };
    }
}
