use crate::{belt_block_raw, from_u32, g5, g13, g21, key_idx, to_u32};
use cipher::{
    AlgorithmName, Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, InOut, Key,
    KeyInit, KeySizeUser, ParBlocksSizeUser,
    consts::{U1, U16, U32},
};
use core::{fmt, mem::swap, num::Wrapping};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// BelT block cipher.
#[derive(Clone)]
pub struct BeltBlock {
    key: [u32; 8],
}

impl KeySizeUser for BeltBlock {
    type KeySize = U32;
}

impl KeyInit for BeltBlock {
    fn new(key: &Key<Self>) -> Self {
        Self { key: to_u32(key) }
    }
}

impl BlockSizeUser for BeltBlock {
    type BlockSize = U16;
}

impl ParBlocksSizeUser for BeltBlock {
    type ParBlocksSize = U1;
}

impl BlockCipherEncrypt for BeltBlock {
    #[inline]
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl BlockCipherEncBackend for BeltBlock {
    #[inline]
    fn encrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        // Encryption as described in section 6.1.3
        // Steps 1 and 4
        let x = to_u32(block.get_in());
        let y = belt_block_raw(x, &self.key);

        let block_out = block.get_out();
        // 6) Y ← b ‖ d ‖ a ‖ c
        *block_out = from_u32(&y).into();
    }
}

impl BlockCipherDecrypt for BeltBlock {
    #[inline]
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl BlockCipherDecBackend for BeltBlock {
    #[inline]
    fn decrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let key = &self.key;
        let block_in: [u32; 4] = to_u32(block.get_in());
        // Steps 1 and 4
        let mut a = Wrapping(block_in[0]);
        let mut b = Wrapping(block_in[1]);
        let mut c = Wrapping(block_in[2]);
        let mut d = Wrapping(block_in[3]);

        // Step 5
        for i in (1..9).rev() {
            // 5.1) b ← b ⊕ G₅(a ⊞ 𝑘[7i])
            b ^= g5(a + key_idx(key, i, 0));
            // 5.2) c ← c ⊕ G₂₁(d ⊞ 𝑘[7i-1])
            c ^= g21(d + key_idx(key, i, 1));
            // 5.3) a ← a ⊟ G₁₃(b ⊞ 𝑘[7i-2])
            a -= g13(b + key_idx(key, i, 2));
            // 5.4) e ← G₂₁(b ⊞ c ⊞ 𝑘[7i-3]) ⊕ ⟨i⟩₃₂
            let e = g21(b + c + key_idx(key, i, 3)) ^ Wrapping(i as u32);
            // 5.5) b ← b ⊞ e
            b += e;
            // 5.6) c ← c ⊟ e
            c -= e;
            // 5.7) d ← d ⊞ G₁₃(c ⊞ 𝑘[7i-4])
            d += g13(c + key_idx(key, i, 4));
            // 5.8) b ← b ⊕ G₂₁(a ⊞ 𝑘[7i-5])
            b ^= g21(a + key_idx(key, i, 5));
            // 5.9) c ← c ⊕ G₅(d ⊞ 𝑘[7i-6])
            c ^= g5(d + key_idx(key, i, 6));
            // 5.10) a ↔ b
            swap(&mut a, &mut b);
            // 5.11) c ↔ d
            swap(&mut c, &mut d);
            // 5.12) a ↔ d
            swap(&mut a, &mut d);
        }

        let block_out = block.get_out();
        // 6) 𝑋 ← c ‖ a ‖ d ‖ b
        let x = [c.0, a.0, d.0, b.0];
        *block_out = from_u32(&x).into();
    }
}

impl AlgorithmName for BeltBlock {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BeltBlock")
    }
}

impl Drop for BeltBlock {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        self.key.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for BeltBlock {}
